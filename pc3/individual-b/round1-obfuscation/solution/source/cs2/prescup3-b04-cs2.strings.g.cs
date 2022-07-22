/*
Copyright 2022 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
namespace x
{
    class MV
    {        
        public static MV Y = new MV();
        public string this[int H] 
        { 
            get 
            { 
                if (G7 == null)
                {
                    // Changed for open-sourcing
                    //using (var K = new MemoryStream(Convert.FromBase64String("AAEAAAD/////AQAAAAAAAAARAQAAAAEAAAAGAgAAABpodHRwOi8vMTAuNS41LjU6NTAwMC9mbGFnMgs=")))
                    using (var K = new MemoryStream(Convert.FromBase64String("AAEAAAD/////AQAAAAAAAAARAQAAAAEAAAAGAgAAABtodHRwOi8vbG9jYWxob3N0OjgwMDAvZmxhZzIL")))
                        G7 = (string[])new BinaryFormatter().Deserialize(K);
                }
                return G7[H]; 
            } 
        }
#if true
        private string[] G7;
#else
      private string[] G7 = new[]{"http://localhost:8000/flag2"};
#endif
    }
}
