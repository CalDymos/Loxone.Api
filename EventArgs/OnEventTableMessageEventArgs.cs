using Loxone.Api.Data.Message;

namespace Loxone.Driver.EventArgs
{
    public class OnEventTableMessageEventArgs : System.EventArgs
    {
        public OnEventTableMessageEventArgs(BinaryMessage message)
        {
            Message = message;
        }

        public BinaryMessage Message { get; }
    }
}
