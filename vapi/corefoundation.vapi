[CCode (cheader_filename = "CoreFoundation/CFDictionary.h", gir_namespace = "Darwin", gir_version = "1.0")]
namespace CoreFoundation {

	//typedef const void *CFTypeRef;
	[Compact]
	[CCode (cname = "const void", ref_function ="CFRetain", unref_function = "CFRelease")]
	public class Type {
		[CCode (cname = "CFShow")]
		public void show(void *obj);

		[CCode (cname = "CFCopyDescription")]
		public String description();

		public string to_string() {
			return description().to_string();
		}
	}

	[CCode (cname = "CFStringEncoding",  cprefix = "kCFStringEncoding", has_type_id = false)]
	public enum StringEncoding {
		MacRoman,
		WindowsLatin1,
		ISOLatin1,
		NextStepLatin,
		ASCII,
		Unicode,
		UTF8,
		NonLossyASCII,
		UTF16,
		UTF16BE,
		UTF16LE,
		UTF32,
		UTF32BE,
		UTF32LE,
	}

	[Compact]
	[CCode (cname = "CFAllocatorRef")]
	public class Allocator {
		[CCode (cname = "CFAllocatorGetDefault")]
		public static Allocator get_default();
		
		[CCode (cname = "CFAllocatorAllocate")]
		//public void * alloc(Index size, CFOptionFlags hint);
		public void* alloc(Index size, long hint);

		//https://developer.apple.com/documentation/corefoundation/cfallocator/predefined_allocators?language=objc
		//[CCode (cname = "kCFAllocatorDefault")]
		//public const Allocator DEFAULT;
	}

	[CCode (cname = "CFIndex", has_type_id = false)]
	public struct Index : long {
	}

	//TODO: inherit CFTypeRef? CFStringRef vs __CFString
	[Compact] 
	[CCode (cname = "const struct __CFString", ref_function ="CFRetain", unref_function = "CFRelease")]    
	public class String : Type {

		[CCode (cname = "CFStringCreateWithCString")]
		public static String from_cstring(Allocator? allocator, uint8* c_str, StringEncoding encoding);

		[CCode (cname = "CFStringGetCString")]
		public bool to_cstring(uint8* buffer, Index buffer_size, StringEncoding encoding);

		[CCode (cname = "CFStringGetLength")]
		public Index length();
		
		[CCode (cname = "CFStringGetMaximumSizeForEncoding")] 
		private static Index max_size_for_encoding(Index length, StringEncoding encoding);
		
		public string to_string() {
			var length = length();
			var max_length = max_size_for_encoding(length, StringEncoding.UTF8) + 1;
			var buffer = new char[max_length];
			//TODO: swich result throw
			to_cstring(buffer, max_length, StringEncoding.UTF8);
			return (string)buffer;
		}

		public static String from_string(string str) {
			return String.from_cstring(null, str,  StringEncoding.UTF8);
		}
	}

	//TODO: cname CFDictionaryRef?
	[Compact] 
	[CCode (cname = "struct __CFDictionary", ref_function ="CFRetain",  unref_function = "CFRelease")]
	public class Dictionary : Type {
		[CCode (cname = "CFDictionaryGetCount")]
		public Index count();
	}


	//TODO: cname CFMutableDictionaryRef?
	[Compact]
	[CCode (cname = "struct __CFDictionary", ref_function = "CFRetain", unref_function = "CFRelease")]
	public class MutableDictionary : Dictionary {
		[CCode (cname = "CFDictionaryAddValue")]
		public void add(void *key, void *value);
		
		[CCode (cname = "CFDictionaryRemoveAllValues")]
		public void clear();

		[CCode (cname = "CFDictionaryRemoveValue")]
		public void remove(void *key);
	}
}
