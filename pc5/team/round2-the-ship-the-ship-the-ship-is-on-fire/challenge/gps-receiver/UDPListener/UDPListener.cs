/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using System;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Linq;

public class UDPConsoleListener
{
    public static void StartListener()
    {
        string currentCoordinates = string.Empty;
        currentCoordinates = ReadGPSCoordinates();

        int port = 11111;
        UdpClient udpClient = new UdpClient(port);
        IPEndPoint ipEndPoint = new IPEndPoint(IPAddress.Any, port);
        bool continueListening = true;

        Console.WriteLine("GPS Receiver is running . . . ");

        while (continueListening)
        {
            try
            {                   
                byte[] bytes = udpClient.Receive(ref ipEndPoint);
                Console.WriteLine("Message Source: " + ipEndPoint.Address.ToString());

                //if(ipEndPoint.Address.ToString() == "127.0.0.1")
                if(ipEndPoint.Address.ToString() == "10.1.1.200")
                {
                    Console.WriteLine($"Received message from GPS client {ipEndPoint} :");
                    currentCoordinates = Encoding.Default.GetString(bytes, 0, bytes.Length);
                    Console.WriteLine(currentCoordinates);

                    if (currentCoordinates.Contains("32.943241")  && currentCoordinates.Contains("-106.419533"))
                    {                        
                        WriteGPSCoordinates(currentCoordinates);
                        ReadGPSCoordinates();
                    }
                }
            }
            catch (Exception exc)
            {
                Console.WriteLine("Error Message: " + exc);
            }            
        }
        
        udpClient.Close();
    }

    private static string ReadGPSCoordinates()
    {
        string currentCoordinates = string.Empty;

        try
        {
            using (var sr = new StreamReader("/home/user/Documents/GPS.txt"))
            {
                currentCoordinates = sr.ReadToEnd();
                Console.WriteLine("Current GPS Destination Coordinates: " + currentCoordinates);
            }
        }    
        catch (Exception exc)
        {
            Console.WriteLine(exc.Message);
        }

        return currentCoordinates;
    }

    private static void WriteGPSCoordinates(string coordinates)
    {
        try
        {
            File.WriteAllText("/home/user/Documents/GPS.txt", coordinates);
        }    
        catch (Exception exc)
        {
            Console.WriteLine(exc.Message);
        }
    }
}

