using System.Reflection;
using fschecker;

Importer importer = new Importer();
importer.DownloadFeatures();

Assembly assembly = System.Reflection.Assembly.LoadFile(AppDomain.CurrentDomain.BaseDirectory + "/modules/" + "chk1.dll");
Type t = assembly.GetType("chk1.Class1");
var methodInfo = t.GetMethod("Run");

if (methodInfo == null)
{
    // throw some exception
}

var o = Activator.CreateInstance(t);
var result = methodInfo.Invoke(o, null);

/////////////////////////////////////////////////////////////////////////////////////////////

Assembly assembly2 = System.Reflection.Assembly.LoadFile(AppDomain.CurrentDomain.BaseDirectory + "/modules/" + "chk2.dll");
Type t2 = assembly2.GetType("chk2.Class1");

var methodInfo2 = t2.GetMethod("Run");

if (methodInfo2 == null)
{
    // throw some exception
}

var o2 = Activator.CreateInstance(t2);
var result2 = methodInfo2.Invoke(o2, null);