using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.IO;

namespace securityService
{
    public partial class securityService : ServiceBase
    {
        public securityService()
        {
            InitializeComponent();
        }
            
        protected override void OnStart(string[] args)
        {
            string path = @"C:\HackCollege\start Up\start.txt";
            if (!File.Exists(path)) {
                var myFile = File.Create(path);
                myFile.Close();
            }
            using (StreamWriter sw = File.AppendText(path))
            {
                sw.WriteLine(DateTime.Now.ToString("yyyy-MM-dd HH':'mm':'ss") + ": security service start");
            }
        }
        protected override void OnSessionChange(SessionChangeDescription changeDescription)
        {
            if (changeDescription.Reason == SessionChangeReason.SessionLogon ||
                changeDescription.Reason == SessionChangeReason.RemoteConnect ||
                changeDescription.Reason == SessionChangeReason.SessionUnlock)
            {
                string path = @"C:\HackCollege\start Up\sessionChange.txt";
                if (!File.Exists(path))
                {
                    var myFile = File.Create(path);
                    myFile.Close();
                }

                
                
                try
                {

                    using (Process myProcess = new Process())
                    {
                        //myProcess.StartInfo.UseShellExecute = false;
                        myProcess.StartInfo.FileName = @"C:\HackCollege\start Up\helper.exe";
                        //myProcess.StartInfo.CreateNoWindow = true;
                        myProcess.Start();
                    }
                    using (StreamWriter sw = File.AppendText(path))
                    {
                        sw.WriteLine(DateTime.Now.ToString("yyyy-MM-dd HH':'mm':'ss") + ": detect " + changeDescription.Reason);
                        sw.WriteLine(DateTime.Now.ToString("yyyy-MM-dd HH':'mm':'ss") + ": start agreement ");
                    }
                }
                catch(Exception e)
                {
                    string errpath = @"C:\HackCollege\start Up\error.txt";
                    if (!File.Exists(errpath))
                    {
                        var myFile = File.Create(errpath);
                        myFile.Close();
                    }
                    using (StreamWriter err = File.AppendText(errpath))
                    {
                        err.WriteLine(DateTime.Now.ToString("yyyy-MM-dd HH':'mm':'ss") + ": "+e.Message);
                    }
                }
            }
        }
        protected override void OnStop()
        {
        }
    }
}
