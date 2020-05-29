using System.Net;
using System;

class auth{
	public static void Main(){
		// Ensure Directory Security settings for default web site in IIS is "Windows Authentication".
		string url = "http://192.168.1.109";
		// Create a 'HttpWebRequest' object with the specified url.
		HttpWebRequest myHttpWebRequest = (HttpWebRequest)WebRequest.Create(url);
		// Assign the credentials of the logged in user or the user being impersonated.
		myHttpWebRequest.Credentials = CredentialCache.DefaultCredentials;
		// Send the 'HttpWebRequest' and wait for response.
		HttpWebResponse myHttpWebResponse = (HttpWebResponse)myHttpWebRequest.GetResponse();
		Console.WriteLine("Authentication successful");
		Console.WriteLine("Response received successfully");
	}
	
}

