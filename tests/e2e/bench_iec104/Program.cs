using lib60870;
using lib60870.CS101;
using lib60870.CS104;

// args: server <port> | client <port>
var mode = args[0];
var port = int.Parse(args[1]);

if (mode == "server")
{
    var server = new Server();
    server.SetLocalAddress("127.0.0.1");
    server.SetLocalPort(port);
    server.SetInterrogationHandler((param, conn, asdu, qoi) =>
    {
        var cp = conn.GetApplicationLayerParameters();
        conn.SendACT_CON(asdu, false);
        var sp = new ASDU(cp, CauseOfTransmission.INTERROGATED_BY_STATION, false, false, 2, 1, false);
        sp.AddInformationObject(new SinglePointInformation(200, true, new QualityDescriptor()));
        sp.AddInformationObject(new SinglePointInformation(201, false, new QualityDescriptor()));
        sp.AddInformationObject(new SinglePointInformation(202, true, new QualityDescriptor()));
        sp.AddInformationObject(new SinglePointInformation(203, false, new QualityDescriptor()));
        conn.SendASDU(sp);
        var mv = new ASDU(cp, CauseOfTransmission.INTERROGATED_BY_STATION, false, false, 2, 1, false);
        mv.AddInformationObject(new MeasuredValueShort(300, 0.25f, new QualityDescriptor()));
        mv.AddInformationObject(new MeasuredValueShort(301, 0.5f, new QualityDescriptor()));
        mv.AddInformationObject(new MeasuredValueShort(302, 0.75f, new QualityDescriptor()));
        conn.SendASDU(mv);
        conn.SendACT_TERM(asdu);
        return true;
    }, null);
    server.Start();
    Console.WriteLine($"LIB60870 SERVER {port}");
    Thread.Sleep(Timeout.Infinite);
}
else if (mode == "client")
{
    var con = new Connection("127.0.0.1", port);
    var received = new List<string>();
    con.SetASDUReceivedHandler((param, asdu) =>
    {
        if (asdu.TypeId == TypeID.M_SP_NA_1)
            for (int i = 0; i < asdu.NumberOfElements; i++)
            {
                var v = (SinglePointInformation)asdu.GetElement(i);
                received.Add($"M_SP {v.ObjectAddress} {(v.Value ? 1 : 0)}");
            }
        else if (asdu.TypeId == TypeID.M_ME_NC_1)
            for (int i = 0; i < asdu.NumberOfElements; i++)
            {
                var v = (MeasuredValueShort)asdu.GetElement(i);
                received.Add($"M_ME_NC {v.ObjectAddress} {v.Value}");
            }
        return true;
    }, null);
    con.Connect();
    Thread.Sleep(300);
    con.SendInterrogationCommand(CauseOfTransmission.ACTIVATION, 1, 20);
    Thread.Sleep(1200);
    foreach (var line in received)
        Console.WriteLine(line);
    Console.WriteLine("CLIENT DONE");
    con.Close();
}
