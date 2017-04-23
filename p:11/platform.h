#ifndef platform_h
#define platform_h

#define CK_PTR *
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
#ifdef __GNUC__

#define CK_DEFINE_FUNCTION(returnType, name) \
  returnType name
#define CK_DECLARE_FUNCTION(returnType, name) \
  returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
  returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) \
  returnType (* name)
#else // !__GNUC__

#if defined(_WIN32) || defined(_WIN64)
#define CK_DEFINE_FUNCTION(returnType, name) \
  returnType __declspec(dllexport) name
#define CK_DECLARE_FUNCTION(returnType, name) \
  returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
  returnType __declspec(dllimport) (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) \
  returnType (* name)

#endif // win32/win64

#endif // __GNUC__

#endif //platform_h
