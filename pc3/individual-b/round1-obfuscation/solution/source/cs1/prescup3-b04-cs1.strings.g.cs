/*
Copyright 2022 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
namespace d
{
    class j
    {        
        public static j I = new j();
        public string this[int f] 
        { 
            get 
            { 
                if (mG == null)
                {
                    // Changed for open-sourcing
                    //using (var Y1 = new MemoryStream(Convert.FromBase64String("AAEAAAD/////AQAAAAAAAAARAQAAAAMAAAAGAgAAABpodHRwOi8vMTAuNS41LjU6NTAwMC9mbGFnMQYDAAAABERhdGEGBAAAAAIsIAs=")))
                    using (var Y1 = new MemoryStream(Convert.FromBase64String("AAEAAAD/////AQAAAAAAAAARAQAAAAMAAAAGAgAAABtodHRwOi8vbG9jYWxob3N0OjgwMDAvZmxhZzEGAwAAAAREYXRhBgQAAAACLCAL")))
                        mG = (string[])new BinaryFormatter().Deserialize(Y1);
                }
                return mG[f]; 
            } 
        }
#if true
        private string[] mG;
#else
      private string[] mG = new[]{"http://localhost:8000/flag1",
"Data",
", "};
#endif
    }
}
