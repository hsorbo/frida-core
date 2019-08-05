namespace Frida {
	public class DarwinHostSessionBackend : Object, HostSessionBackend {
		private DarwinHostSessionProvider local_provider;

		public async void start (Cancellable? cancellable) throws IOError {
			assert (local_provider == null);
			local_provider = new DarwinHostSessionProvider ();
			provider_available (local_provider);
		}

		public async void stop (Cancellable? cancellable) throws IOError {
			assert (local_provider != null);
			provider_unavailable (local_provider);
			yield local_provider.close (cancellable);
			local_provider = null;
		}
	}

	public class DarwinHostSessionProvider : Object, HostSessionProvider {
		public string id {
			get { return "local"; }
		}

		public string name {
			get { return "Local System"; }
		}

		public Image? icon {
			get { return _icon; }
		}
		private Image? _icon;

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.LOCAL; }
		}

		private DarwinHostSession host_session;

		construct {
			_icon = Image.from_data (_try_extract_icon ());
		}

		public async void close (Cancellable? cancellable) throws IOError {
			if (host_session == null)
				return;
			host_session.agent_session_closed.disconnect (on_agent_session_closed);
			yield host_session.close (cancellable);
			host_session = null;
		}

		public async HostSession create (string? location, Cancellable? cancellable) throws Error, IOError {
			assert (location == null);
			if (host_session != null)
				throw new Error.INVALID_ARGUMENT ("Invalid location: already created");
			var tempdir = new TemporaryDirectory ();
			host_session = new DarwinHostSession (new DarwinHelperProcess (tempdir), tempdir);
			host_session.agent_session_closed.connect (on_agent_session_closed);
			return host_session;
		}

		public async void destroy (HostSession session, Cancellable? cancellable) throws Error, IOError {
			if (session != host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");
			host_session.agent_session_closed.disconnect (on_agent_session_closed);
			yield host_session.close (cancellable);
			host_session = null;
		}

		public async AgentSession obtain_agent_session (HostSession host_session, AgentSessionId agent_session_id,
				Cancellable? cancellable) throws Error, IOError {
			if (host_session != this.host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");
			return this.host_session.obtain_agent_session (agent_session_id);
		}

		private void on_agent_session_closed (AgentSessionId id, AgentSession session, SessionDetachReason reason,
				CrashInfo? crash) {
			agent_session_closed (id, reason, crash);
		}

		public extern static ImageData? _try_extract_icon ();
	}

	public class DarwinHostSession : BaseDBusHostSession {
		public DarwinHelper helper {
			get;
			construct;
		}

		public TemporaryDirectory tempdir {
			get;
			construct;
		}

		private Fruitjector fruitjector;
		private AgentResource? agent;
#if IOS
		private FruitController fruit_controller;
#endif

		private ApplicationEnumerator application_enumerator = new ApplicationEnumerator ();
		private ProcessEnumerator process_enumerator = new ProcessEnumerator ();

		public DarwinHostSession (owned DarwinHelper helper, owned TemporaryDirectory tempdir) {
			Object (helper: helper, tempdir: tempdir);
		}

		construct {
			helper.output.connect (on_output);
			helper.spawn_added.connect (on_spawn_added);
			helper.spawn_removed.connect (on_spawn_removed);

			fruitjector = new Fruitjector (helper, false, tempdir);
			injector = fruitjector;
			fruitjector.injected.connect (on_injected);
			injector.uninjected.connect (on_uninjected);

			var blob = Frida.Data.Agent.get_frida_agent_dylib_blob ();
			agent = new AgentResource (blob.name, new Bytes.static (blob.data), tempdir);

#if IOS
			fruit_controller = new FruitController (this, io_cancellable);
			fruit_controller.spawn_added.connect (on_spawn_added);
			fruit_controller.spawn_removed.connect (on_spawn_removed);
			fruit_controller.process_crashed.connect (on_process_crashed);
#endif
		}

		public override async void close (Cancellable? cancellable) throws IOError {
			yield base.close (cancellable);

#if IOS
			yield fruit_controller.close (cancellable);
			fruit_controller.spawn_added.disconnect (on_spawn_added);
			fruit_controller.spawn_removed.disconnect (on_spawn_removed);
			fruit_controller.process_crashed.disconnect (on_process_crashed);
#endif

			var fruitjector = injector as Fruitjector;

			yield wait_for_uninject (injector, cancellable, () => {
				return fruitjector.any_still_injected ();
			});

			agent = null;

			fruitjector.injected.disconnect (on_injected);
			injector.uninjected.disconnect (on_uninjected);
			yield injector.close (cancellable);

			yield helper.close (cancellable);
			helper.output.disconnect (on_output);
			helper.spawn_added.disconnect (on_spawn_added);
			helper.spawn_removed.disconnect (on_spawn_removed);

			tempdir.destroy ();
		}

		protected override async AgentSessionProvider create_system_session_provider (Cancellable? cancellable,
				out DBusConnection connection) throws Error, IOError {
			yield helper.preload (cancellable);

			var pid = helper.pid;

			string remote_address;
			var stream_request = yield helper.open_pipe_stream (pid, cancellable, out remote_address);

			var fruitjector = injector as Fruitjector;
			var id = yield fruitjector.inject_library_resource (pid, agent, "frida_agent_main", remote_address, cancellable);
			injectee_by_pid[pid] = id;

			IOStream stream = yield stream_request.wait_async (cancellable);

			DBusConnection conn;
			AgentSessionProvider provider;
			try {
				conn = yield new DBusConnection (stream, ServerGuid.HOST_SESSION_SERVICE,
					AUTHENTICATION_SERVER | AUTHENTICATION_ALLOW_ANONYMOUS, null, cancellable);

				provider = yield conn.get_proxy (null, ObjectPath.AGENT_SESSION_PROVIDER, DBusProxyFlags.NONE, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			connection = conn;

			return provider;
		}

		public override async HostApplicationInfo get_frontmost_application (Cancellable? cancellable) throws Error, IOError {
			return System.get_frontmost_application ();
		}

		public override async HostApplicationInfo[] enumerate_applications (Cancellable? cancellable) throws Error, IOError {
			return yield application_enumerator.enumerate_applications ();
		}

		public override async HostProcessInfo[] enumerate_processes (Cancellable? cancellable) throws Error, IOError {
			return yield process_enumerator.enumerate_processes ();
		}

		public override async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
#if IOS
			yield fruit_controller.enable_spawn_gating (cancellable);
#else
			yield helper.enable_spawn_gating (cancellable);
#endif
		}

		public override async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
#if IOS
			yield fruit_controller.disable_spawn_gating (cancellable);
#else
			yield helper.disable_spawn_gating (cancellable);
#endif
		}

		public override async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws Error, IOError {
#if IOS
			return fruit_controller.enumerate_pending_spawn ();
#else
			return yield helper.enumerate_pending_spawn (cancellable);
#endif
		}

		public override async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable)
				throws Error, IOError {
#if IOS
			if (!program.has_prefix ("/"))
				return yield fruit_controller.spawn (program, options, cancellable);
#endif

			return yield helper.spawn (program, options, cancellable);
		}

		protected override async void await_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			yield helper.wait_until_suspended (pid, cancellable);
			yield helper.notify_exec_completed (pid, cancellable);
		}

		protected override async void cancel_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			yield helper.cancel_pending_waits (pid, cancellable);
		}

		protected override bool process_is_alive (uint pid) {
			return Posix.kill ((Posix.pid_t) pid, 0) == 0 || Posix.errno == Posix.EPERM;
		}

		public override async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError {
			yield helper.input (pid, data, cancellable);
		}

		protected override async void perform_resume (uint pid, Cancellable? cancellable) throws Error, IOError {
#if IOS
			if (yield fruit_controller.try_resume (pid, cancellable))
				return;
#endif

			yield helper.resume (pid, cancellable);
		}

		public override async void kill (uint pid, Cancellable? cancellable) throws Error, IOError {
			yield helper.kill_process (pid, cancellable);
		}

		protected override async Future<IOStream> perform_attach_to (uint pid, Cancellable? cancellable, out Object? transport)
				throws Error, IOError {
			transport = null;

			yield wait_for_uninject (injector, cancellable, () => {
				return injectee_by_pid.has_key (pid);
			});

			string remote_address;
			var stream_future = yield helper.open_pipe_stream (pid, cancellable, out remote_address);

			var fruitjector = injector as Fruitjector;
			var id = yield fruitjector.inject_library_resource (pid, agent, "frida_agent_main", remote_address, cancellable);
			injectee_by_pid[pid] = id;

			return stream_future;
		}

#if IOS
		public void activate_crash_reporter_integration () {
			fruit_controller.activate_crash_reporter_integration ();
		}

		protected override async CrashInfo? try_collect_crash (uint pid, Cancellable? cancellable) throws IOError {
			return yield fruit_controller.try_collect_crash (pid, cancellable);
		}
#endif

		private void on_output (uint pid, int fd, uint8[] data) {
			output (pid, fd, data);
		}

		private void on_spawn_added (HostSpawnInfo info) {
			spawn_added (info);
		}

		private void on_spawn_removed (HostSpawnInfo info) {
			spawn_removed (info);
		}

#if IOS
		private void on_process_crashed (CrashInfo info) {
			process_crashed (info);
		}
#endif

		private void on_injected (uint id, uint pid, bool has_mapped_module, DarwinModuleDetails mapped_module) {
#if IOS
			DarwinModuleDetails? mapped_module_value = null;
			if (has_mapped_module)
				mapped_module_value = mapped_module;
			fruit_controller.on_agent_injected (id, pid, mapped_module_value);
#endif
		}

		private void on_uninjected (uint id) {
#if IOS
			fruit_controller.on_agent_uninjected (id);
#endif

			foreach (var entry in injectee_by_pid.entries) {
				if (entry.value == id) {
					injectee_by_pid.unset (entry.key);
					return;
				}
			}

			uninjected (InjectorPayloadId (id));
		}
	}

#if IOS
	private class FruitController : Object, MappedAgentContainer {
		public signal void spawn_added (HostSpawnInfo info);
		public signal void spawn_removed (HostSpawnInfo info);
		public signal void process_crashed (CrashInfo crash);

		public weak DarwinHostSession host_session {
			get;
			construct;
		}

		public DarwinHelper helper {
			get;
			construct;
		}

		public Cancellable io_cancellable {
			get;
			construct;
		}

		private LaunchdAgent launchd_agent;
		private bool spawn_gating_enabled = false;
		private Gee.HashMap<string, Promise<uint>> spawn_requests = new Gee.HashMap<string, Promise<uint>> ();
		private Gee.HashMap<uint, HostSpawnInfo?> pending_spawn = new Gee.HashMap<uint, HostSpawnInfo?> ();
		private Gee.HashMap<uint, ReportCrashAgent> crash_agents = new Gee.HashMap<uint, ReportCrashAgent> ();
		private Gee.HashMap<uint, CrashDelivery> crash_deliveries = new Gee.HashMap<uint, CrashDelivery> ();
		private Gee.HashMap<uint, MappedAgent> mapped_agents = new Gee.HashMap<uint, MappedAgent> ();
		private Gee.HashMap<MappedAgent, Source> mapped_agents_dying = new Gee.HashMap<MappedAgent, Source> ();
		private Gee.HashSet<uint> xpcproxies = new Gee.HashSet<uint> ();

		public FruitController (DarwinHostSession host_session, Cancellable io_cancellable) {
			Object (
				host_session: host_session,
				helper: host_session.helper,
				io_cancellable: io_cancellable
			);
		}

		construct {
			launchd_agent = new LaunchdAgent (host_session, io_cancellable);
			launchd_agent.app_launch_started.connect (on_app_launch_started);
			launchd_agent.app_launch_completed.connect (on_app_launch_completed);
			launchd_agent.spawn_preparation_started.connect (on_spawn_preparation_started);
			launchd_agent.spawn_preparation_aborted.connect (on_spawn_preparation_aborted);
			launchd_agent.spawn_captured.connect (on_spawn_captured);
		}

		~FruitController () {
			launchd_agent.spawn_captured.disconnect (on_spawn_captured);
			launchd_agent.spawn_preparation_aborted.disconnect (on_spawn_preparation_aborted);
			launchd_agent.spawn_preparation_started.disconnect (on_spawn_preparation_started);
			launchd_agent.app_launch_completed.disconnect (on_app_launch_completed);
			launchd_agent.app_launch_started.disconnect (on_app_launch_started);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			if (spawn_gating_enabled) {
				try {
					yield disable_spawn_gating (cancellable);
				} catch (Error e) {
				}
			}

			yield launchd_agent.close (cancellable);
		}

		public async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			yield launchd_agent.enable_spawn_gating (cancellable);

			spawn_gating_enabled = true;
		}

		public async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			spawn_gating_enabled = false;

			yield launchd_agent.disable_spawn_gating (cancellable);

			var pending = pending_spawn.values.to_array ();
			pending_spawn.clear ();
			foreach (var spawn in pending) {
				spawn_removed (spawn);

				helper.resume.begin (spawn.pid, io_cancellable);
			}
		}

		public HostSpawnInfo[] enumerate_pending_spawn () {
			var result = new HostSpawnInfo[pending_spawn.size];
			var index = 0;
			foreach (var spawn in pending_spawn.values)
				result[index++] = spawn;
			return result;
		}

		public async uint spawn (string identifier, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError {
			if (spawn_requests.has_key (identifier))
				throw new Error.INVALID_OPERATION ("Spawn already in progress for the specified identifier");

			var request = new Promise<uint> ();
			spawn_requests[identifier] = request;

			uint pid = 0;
			try {
				yield launchd_agent.prepare_for_launch (identifier, cancellable);

				yield helper.launch (identifier, options, cancellable);

				var timeout = new TimeoutSource.seconds (20);
				timeout.set_callback (() => {
					request.reject (new Error.TIMED_OUT ("Unexpectedly timed out while waiting for app to launch"));
					return false;
				});
				timeout.attach (MainContext.get_thread_default ());
				try {
					pid = yield request.future.wait_async (cancellable);
				} finally {
					timeout.destroy ();
				}

				helper.notify_launch_completed.begin (identifier, pid, io_cancellable);
			} catch (GLib.Error e) {
				launchd_agent.cancel_launch.begin (identifier, io_cancellable);

				if (!spawn_requests.unset (identifier)) {
					var pending_pid = request.future.value;
					if (pending_pid != 0)
						helper.resume.begin (pending_pid, io_cancellable);
				}

				throw_api_error (e);
			}

			return pid;
		}

		public async bool try_resume (uint pid, Cancellable? cancellable) throws Error, IOError {
			HostSpawnInfo? info;
			if (!pending_spawn.unset (pid, out info))
				return false;
			spawn_removed (info);

			yield helper.resume (pid, cancellable);

			return true;
		}

		public void activate_crash_reporter_integration () {
			launchd_agent.activate_crash_reporter_integration ();
		}

		public async CrashInfo? try_collect_crash (uint pid, Cancellable? cancellable) throws IOError {
			if (crash_agents.has_key (pid) || xpcproxies.contains (pid))
				return null;

			var delivery = get_crash_delivery_for_pid (pid);
			try {
				return yield delivery.future.wait_async (cancellable);
			} catch (Error e) {
				return null;
			}
		}

		public void enumerate_mapped_agents (FoundMappedAgentFunc func) {
			foreach (var mapped_agent in mapped_agents.values)
				func (mapped_agent);
		}

		public void on_agent_injected (uint id, uint pid, DarwinModuleDetails? mapped_module) {
			if (mapped_module == null)
				return;

			var dead_agents = new Gee.ArrayList<MappedAgent> ();
			foreach (var agent in mapped_agents_dying.keys) {
				if (agent.pid == pid)
					dead_agents.add (agent);
			}
			foreach (var agent in dead_agents) {
				Source source;
				mapped_agents_dying.unset (agent, out source);
				source.destroy ();

				mapped_agents.unset (agent.id);
			}

			mapped_agents[id] = new MappedAgent (id, pid, mapped_module);
		}

		public void on_agent_uninjected (uint id) {
			var agent = mapped_agents[id];
			if (agent == null)
				return;

			var timeout = new TimeoutSource.seconds (20);
			timeout.set_callback (() => {
				mapped_agents.unset (id);
				return false;
			});
			timeout.attach (MainContext.get_thread_default ());
			mapped_agents_dying[agent] = timeout;
		}

		private void on_app_launch_started (string identifier, uint pid) {
			xpcproxies.add (pid);
		}

		private void on_app_launch_completed (string identifier, uint pid, GLib.Error? error) {
			xpcproxies.remove (pid);

			Promise<uint> request;
			if (spawn_requests.unset (identifier, out request)) {
				if (error == null)
					request.resolve (pid);
				else
					request.reject (error);
			} else {
				if (error == null)
					helper.resume.begin (pid, io_cancellable);
			}
		}

		private void on_spawn_preparation_started (HostSpawnInfo info) {
			xpcproxies.add (info.pid);

			if (is_crash_reporter (info))
				add_crash_reporter_agent (info.pid);
		}

		private void on_spawn_preparation_aborted (HostSpawnInfo info) {
			xpcproxies.remove (info.pid);
			crash_agents.unset (info.pid);
		}

		private void on_spawn_captured (HostSpawnInfo info) {
			xpcproxies.remove (info.pid);
			handle_spawn.begin (info);
		}

		private async void handle_spawn (HostSpawnInfo info) {
			try {
				var pid = info.pid;

				var crash_agent = crash_agents[pid];
				if (crash_agent != null) {
					try {
						yield crash_agent.start (io_cancellable);
					} catch (GLib.Error e) {
						crash_agents.unset (pid);
					}
				}

				if (!spawn_gating_enabled) {
					yield helper.resume (pid, io_cancellable);
					return;
				}

				pending_spawn[pid] = info;
				spawn_added (info);
			} catch (GLib.Error e) {
			}
		}

		private ReportCrashAgent add_crash_reporter_agent (uint pid) {
			foreach (var delivery in crash_deliveries.values)
				delivery.extend_timeout (5000);

			var agent = new ReportCrashAgent (host_session, pid, this, io_cancellable);
			crash_agents[pid] = agent;

			agent.unloaded.connect (on_crash_agent_unloaded);
			agent.crash_detected.connect (on_crash_detected);
			agent.crash_received.connect (on_crash_received);

			return agent;
		}

		private void on_crash_agent_unloaded (InternalAgent agent) {
			var crash_agent = agent as ReportCrashAgent;
			crash_agents.unset (crash_agent.pid);
		}

		private void on_crash_detected (ReportCrashAgent agent, uint pid) {
			var delivery = get_crash_delivery_for_pid (pid);
			delivery.extend_timeout ();
		}

		private void on_crash_received (ReportCrashAgent agent, CrashInfo crash) {
			var delivery = get_crash_delivery_for_pid (crash.pid);
			delivery.complete (crash);

			process_crashed (crash);
		}

		private static bool is_crash_reporter (HostSpawnInfo info) {
			return info.identifier == "com.apple.ReportCrash";
		}

		private CrashDelivery get_crash_delivery_for_pid (uint pid) {
			var delivery = crash_deliveries[pid];
			if (delivery == null) {
				delivery = new CrashDelivery (pid);
				delivery.expired.connect (on_crash_delivery_expired);
				crash_deliveries[pid] = delivery;
			}
			return delivery;
		}

		private void on_crash_delivery_expired (CrashDelivery delivery) {
			crash_deliveries.unset (delivery.pid);
		}

		private class CrashDelivery : Object {
			public signal void expired ();

			public uint pid {
				get;
				construct;
			}

			public Future<CrashInfo?> future {
				get {
					return promise.future;
				}
			}

			private Promise<CrashInfo?> promise = new Promise <CrashInfo?> ();
			private TimeoutSource expiry_source;

			public CrashDelivery (uint pid) {
				Object (pid: pid);
			}

			construct {
				expiry_source = make_expiry_source (500);
			}

			private TimeoutSource make_expiry_source (uint timeout) {
				var source = new TimeoutSource (timeout);
				source.set_callback (on_timeout);
				source.attach (MainContext.get_thread_default ());
				return source;
			}

			public void extend_timeout (uint timeout = 20000) {
				if (future.ready)
					return;

				expiry_source.destroy ();
				expiry_source = make_expiry_source (timeout);
			}

			public void complete (CrashInfo? crash) {
				if (future.ready)
					return;

				promise.resolve (crash);

				expiry_source.destroy ();
				expiry_source = make_expiry_source (1000);
			}

			private bool on_timeout () {
				if (!future.ready)
					promise.reject (new Error.TIMED_OUT ("Crash delivery timed out"));

				expired ();

				return false;
			}
		}
	}

	private interface MappedAgentContainer : Object {
		public abstract void enumerate_mapped_agents (FoundMappedAgentFunc func);
	}

	private delegate void FoundMappedAgentFunc (MappedAgent agent);

	private class MappedAgent {
		public uint id {
			get;
			private set;
		}

		public uint pid {
			get;
			private set;
		}

		public DarwinModuleDetails module {
			get;
			private set;
		}

		public MappedAgent (uint id, uint pid, DarwinModuleDetails module) {
			this.id = id;
			this.pid = pid;
			this.module = module;
		}
	}

	private class LaunchdAgent : InternalAgent {
		public signal void app_launch_started (string identifier, uint pid);
		public signal void app_launch_completed (string identifier, uint pid, GLib.Error? error);
		public signal void spawn_preparation_started (HostSpawnInfo info);
		public signal void spawn_preparation_aborted (HostSpawnInfo info);
		public signal void spawn_captured (HostSpawnInfo info);

		public Cancellable io_cancellable {
			get;
			construct;
		}

		public LaunchdAgent (DarwinHostSession host_session, Cancellable io_cancellable) {
			string * source = Frida.Data.Darwin.get_launchd_js_blob ().data;
			Object (
				host_session: host_session,
				script_source: source,
				io_cancellable: io_cancellable
			);
		}

		public void activate_crash_reporter_integration () {
			ensure_loaded.begin (io_cancellable);
		}

		public async void prepare_for_launch (string identifier, Cancellable? cancellable) throws Error, IOError {
			yield call ("prepareForLaunch", new Json.Node[] { new Json.Node.alloc ().init_string (identifier) }, cancellable);
		}

		public async void cancel_launch (string identifier, Cancellable? cancellable) throws Error, IOError {
			yield call ("cancelLaunch", new Json.Node[] { new Json.Node.alloc ().init_string (identifier) }, cancellable);
		}

		public async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			yield call ("enableSpawnGating", new Json.Node[] {}, cancellable);
		}

		public async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			yield call ("disableSpawnGating", new Json.Node[] {}, cancellable);
		}

		protected override void on_event (string type, Json.Array event) {
			var identifier = event.get_string_element (1);
			var pid = (uint) event.get_int_element (2);

			switch (type) {
				case "launch:app":
					prepare_app.begin (identifier, pid);
					break;
				case "spawn":
					prepare_xpcproxy.begin (identifier, pid);
					break;
				default:
					assert_not_reached ();
			}
		}

		private async void prepare_app (string identifier, uint pid) {
			app_launch_started (identifier, pid);

			try {
				var agent = new XpcProxyAgent (host_session as DarwinHostSession, identifier, pid);
				yield agent.run_until_exec (io_cancellable);
				app_launch_completed (identifier, pid, null);
			} catch (GLib.Error e) {
				app_launch_completed (identifier, pid, e);
			}
		}

		private async void prepare_xpcproxy (string identifier, uint pid) {
			var info = HostSpawnInfo (pid, identifier);
			spawn_preparation_started (info);

			try {
				var agent = new XpcProxyAgent (host_session as DarwinHostSession, identifier, pid);
				yield agent.run_until_exec (io_cancellable);
				spawn_captured (info);
			} catch (GLib.Error e) {
				spawn_preparation_aborted (info);
			}
		}

		protected override async uint get_target_pid (Cancellable? cancellable) throws Error, IOError {
			return 1;
		}
	}

	private class XpcProxyAgent : InternalAgent {
		public string identifier {
			get;
			construct;
		}

		public uint pid {
			get;
			construct;
		}

		public XpcProxyAgent (DarwinHostSession host_session, string identifier, uint pid) {
			string * source = Frida.Data.Darwin.get_xpcproxy_js_blob ().data;
			Object (host_session: host_session, script_source: source, identifier: identifier, pid: pid);
		}

		public async void run_until_exec (Cancellable? cancellable) throws Error, IOError {
			yield ensure_loaded (cancellable);

			var helper = (host_session as DarwinHostSession).helper;
			yield helper.resume (pid, cancellable);

			yield wait_for_unload (cancellable);

			yield helper.wait_until_suspended (pid, cancellable);
			yield helper.notify_exec_completed (pid, cancellable);
		}

		protected override async uint get_target_pid (Cancellable? cancellable) throws Error, IOError {
			return pid;
		}
	}

	private class ReportCrashAgent : InternalAgent {
		public signal void crash_detected (uint pid);
		public signal void crash_received (CrashInfo crash);

		public uint pid {
			get;
			construct;
		}

		public MappedAgentContainer mapped_agent_container {
			get;
			construct;
		}

		public Cancellable io_cancellable {
			get;
			construct;
		}

		public ReportCrashAgent (DarwinHostSession host_session, uint pid, MappedAgentContainer mapped_agent_container,
				Cancellable io_cancellable) {
			string * source = Frida.Data.Darwin.get_reportcrash_js_blob ().data;
			Object (
				host_session: host_session,
				script_source: source,
				pid: pid,
				mapped_agent_container: mapped_agent_container,
				io_cancellable: io_cancellable
			);
		}

		public async void start (Cancellable? cancellable) throws Error, IOError {
			yield ensure_loaded (cancellable);
		}

		protected override void on_event (string type, Json.Array event) {
			switch (type) {
				case "crash-detected":
					var pid = (uint) event.get_int_element (1);

					send_mapped_agents (pid);

					crash_detected (pid);

					break;
				case "crash-received":
					var pid = (uint) event.get_int_element (1);
					var raw_report = event.get_string_element (2);

					var crash = parse_report (pid, raw_report);
					crash_received (crash);

					break;
				default:
					assert_not_reached ();
			}
		}

		private static CrashInfo parse_report (uint pid, string raw_report) {
			var tokens = raw_report.split ("\n", 2);
			var raw_header = tokens[0];
			var report = tokens[1];

			var parameters = new VariantDict ();
			try {
				var header = new Json.Reader (Json.from_string (raw_header));
				foreach (string member in header.list_members ()) {
					header.read_member (member);

					Variant? val = null;
					if (header.is_value ()) {
						Json.Node node = header.get_value ();
						Type t = node.get_value_type ();
						if (t == typeof (string))
							val = new Variant.string (node.get_string ());
						else if (t == typeof (int64))
							val = new Variant.int64 (node.get_int ());
						else if (t == typeof (bool))
							val = new Variant.boolean (node.get_boolean ());
					}

					if (val != null)
						parameters.insert_value (canonicalize_parameter_name (member), val);

					header.end_member ();
				}
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			string? process_name = null;
			parameters.lookup ("name", "s", out process_name);
			assert (process_name != null);

			string summary = summarize (report);

			return CrashInfo (pid, process_name, summary, report, parameters.end ());
		}

		private static string summarize (string report) {
			MatchInfo info;

			string? exception_type = null;
			if (/^Exception Type: +(.+)$/m.match (report, 0, out info)) {
				exception_type = info.fetch (1);
			}

			string? exception_subtype = null;
			if (/^Exception Subtype: +(.+)$/m.match (report, 0, out info)) {
				exception_subtype = info.fetch (1);
			}

			string? signal_description = null;
			if (/^Termination Signal: +(.+): \d+$/m.match (report, 0, out info)) {
				signal_description = info.fetch (1);
			}

			string? reason_namespace = null;
			string? reason_code = null;
			if (/^Termination Reason: +Namespace (.+), Code (.+)$/m.match (report, 0, out info)) {
				reason_namespace = info.fetch (1);
				reason_code = info.fetch (2);
			}

			if (reason_namespace == null)
				return "Unknown error";

			if (reason_namespace == "SIGNAL") {
				if (exception_subtype != null) {
					string? problem = null;
					if (exception_type != null && /^EXC_(\w+)/.match (exception_type, 0, out info)) {
						string raw_problem = info.fetch (1).replace ("_", " ");
						problem = "%c%s".printf (raw_problem[0].toupper (), raw_problem.substring (1).down ());
					}

					string? cause = null;
					if (/^KERN_(.+) at /.match (exception_subtype, 0, out info)) {
						cause = info.fetch (1).replace ("_", " ").down ();
					}

					if (problem != null && cause != null)
						return "%s due to %s".printf (problem, cause);
				}

				if (signal_description != null)
					return signal_description;
			}

			if (reason_namespace == "CODESIGNING")
				return "Codesigning violation";

			if (reason_namespace == "JETSAM" && exception_subtype != null)
				return "Jetsam %s budget exceeded".printf (exception_subtype.down ());

			return "Unknown %s error %s".printf (reason_namespace.down (), reason_code);
		}

		private void send_mapped_agents (uint pid) {
			var stanza = new Json.Builder ();
			stanza
				.begin_object ()
				.set_member_name ("type")
				.add_string_value ("mapped-agents")
				.set_member_name ("payload")
				.begin_array ();
			mapped_agent_container.enumerate_mapped_agents (agent => {
				if (agent.pid == pid) {
					DarwinModuleDetails details = agent.module;

					stanza
						.begin_object ()
						.set_member_name ("machHeaderAddress")
						.add_string_value (details.mach_header_address.to_string ())
						.set_member_name ("uuid")
						.add_string_value (details.uuid)
						.set_member_name ("path")
						.add_string_value (details.path)
						.end_object ();
				}
			});
			stanza
				.end_array ()
				.end_object ();
			string raw_stanza = Json.to_string (stanza.get_root (), false);

			session.post_to_script.begin (script, raw_stanza, false, new uint8[0], io_cancellable);
		}

		private static string canonicalize_parameter_name (string name) {
			var result = new StringBuilder ();

			unichar c;
			bool need_underscore = true;
			for (int i = 0; name.get_next_char (ref i, out c);) {
				if (c.isupper ()) {
					if (i != 0 && need_underscore) {
						result.append_c ('_');
						need_underscore = false;
					}

					c = c.tolower ();
				} else {
					need_underscore = true;
				}

				result.append_unichar (c);
			}

			return result.str;
		}

		protected override async uint get_target_pid (Cancellable? cancellable) throws Error, IOError {
			return pid;
		}
	}
#endif
}
