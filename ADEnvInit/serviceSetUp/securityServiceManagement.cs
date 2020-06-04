using System.ServiceProcess;

namespace securityServiceManagement
{
    public partial class Service1 : ServiceBase
    {
        public Service1()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
        }

        protected override void OnStop()
        {
        }

        protected override void OnSessionChange(SessionChangeDescription changeDescription)
        {
            base.OnSessionChange(changeDescription);
            /*
             Three type changeDescription.Reason
             1.SessionChangeReason.SessionLogon
             2.SessionChangeReason.SessionLogoff:
             3.SessionChangeReason.RemoteConnect
             4.SessionChangeReason.RemoteDisconnect:
             5.SessionChangeReason.SessionLock
             6.SessionChangeReason.SessionUnlock:    
             */
            if (changeDescription.Reason == SessionChangeReason.SessionLogon ||
                changeDescription.Reason == SessionChangeReason.RemoteConnect ||
                changeDescription.Reason == SessionChangeReason.SessionUnlock)
            {
                ServiceController service = new ServiceController("securityService");
                if (service.Status.Equals(ServiceControllerStatus.Stopped) ||
                    service.Status.Equals(ServiceControllerStatus.StopPending))
                {
                    service.Start();
                }


            }
        }
    }
}
