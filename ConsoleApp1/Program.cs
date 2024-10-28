using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Xml.Linq;
using System.Net;
//using Nest;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace ConsoleApp1
{
    public class ProcessEvent
    {
        public string ProcessName { get; set; }
        public int ProcessId { get; set; }
        public string CommandLine { get; set; }
        public DateTime Timestamp { get; set; }
        public string EventType { get; set; }
    }

    public class TcpIpEvent
    {

        public string EventName { get; set; }
        public string SourceIpv4Address { get; set; }
        public string DestIpv4Address { get; set; }
        public bool IsBlacklisted { get; set; }
        public DateTime Timestamp { get; set; }
    }

    class Program
    {
        static FileSystemWatcher watcher;
        static TraceEventSession traceEventSession;
        static HashSet<string> monitoredProcesses;
        static HashSet<string> blacklistIPs;
        static Dictionary<int, string> ncProcesses = new Dictionary<int, string>();
        static Dictionary<int, string> processNames = new Dictionary<int, string>();
        private static List<int> toRemove = new List<int>();

        //private static ElasticClient client;

        static void Main(string[] args)
        {
            var uri = new Uri("http://localhost:9200");

            //var settings = new ConnectionSettings(uri);

            //client = new ElasticClient(settings);
            //var response = client.Ping();
            //if (response.IsValid)
            //{
            //    Console.WriteLine("Successfully connected to Elasticsearch.");
            //}
            //else
            //{
            //    Console.WriteLine("Failed to connect to Elasticsearch.");
            //}

            if (!(TraceEventSession.IsElevated() ?? false))
            {
                Console.WriteLine("Please run me as administrator");
                return;
            }

            // 读取 XML 配置文件
            var config = XDocument.Load("C:\\Users\\frank\\OneDrive\\桌面\\etw\\etwrole.xml");
            var watcherConfig = config.Element("Configuration").Element("FileSystemWatcherConfig");
            var processMonitorConfig = config.Element("Configuration").Element("ProcessMonitorConfig");
            var blacklistrConfig = config.Element("Configuration").Element("blacklist");

            monitoredProcesses = new HashSet<string>();
            blacklistIPs = new HashSet<string>();

            if (processMonitorConfig != null)
            {
                foreach (var name in processMonitorConfig.Elements("Name"))
                {
                    monitoredProcesses.Add(name.Value);
                    Console.WriteLine("Added to monitoring: " + name.Value);
                }
            }

            foreach (var ip in config.Element("Configuration").Element("Blacklists").Elements("IP"))
            {
                blacklistIPs.Add(ip.Value);
            }

            // 初始化 ETW
            InitializeETW();
            //InitializeTCPIP();

            // 使用配置文件初始化 FileSystemWatcher
            InitializeFileSystemWatcher(
                watcherConfig.Element("Path").Value,
                watcherConfig.Element("Filter").Value,
                watcherConfig.Element("NotifyFilter").Value
            );

            Console.WriteLine("Monitoring started. Press 'Enter' to quit.");
            Console.ReadLine();

            watcher.EnableRaisingEvents = false;
            watcher.Dispose();
            traceEventSession.Dispose();
        }

        static void InitializeETW()
        {
            traceEventSession = new TraceEventSession("MyETWSession");
            traceEventSession.EnableKernelProvider(
                    KernelTraceEventParser.Keywords.NetworkTCPIP |
                    KernelTraceEventParser.Keywords.Process |
                    KernelTraceEventParser.Keywords.ImageLoad);
            traceEventSession.EnableProvider("Microsoft-Windows-TCPIP");

            // ProcessStart
            traceEventSession.Source.Kernel.ProcessStart += data =>
            {
                //var processEvent = new ProcessEvent
                //{
                //    ProcessName = data.ProcessName,
                //    ProcessId = data.ProcessID,
                //    CommandLine = data.CommandLine,
                //    Timestamp = DateTime.UtcNow,
                //    EventType = "ProcessStart"
                //};

                OnProcessStarted(data);
                //indexdatatoelasticsearch(processevent, "etw-events");
                if (data.ProcessName.ToLower().Contains("nc"))
                {
                    Console.WriteLine($"NC process started: {data.ProcessName} (PID: {data.ProcessID})");

                    string filePath = GetProcessFilePath(data.ProcessID);
                    if (!string.IsNullOrEmpty(filePath))
                    {
                        Console.WriteLine($"File Path: {filePath}");
                        ComputeHashes(filePath);
                    }
                }
            };

            traceEventSession.Source.Kernel.ProcessStop += data =>
            {
                var processEvent = new ProcessEvent
                {
                    ProcessName = data.ProcessName,
                    ProcessId = data.ProcessID,
                    CommandLine = data.CommandLine,
                    Timestamp = DateTime.UtcNow,
                    EventType = "ProcessStop"
                };
                OnProcessStopped(data);
                //IndexDataToElasticsearch(processEvent, "etw-events");
            };

            //TCPIP
            //traceEventSession.Source.Dynamic.All += data =>
            //{
            //    if (data.ProviderName == "Microsoft-Windows-TCPIP" && data.EventName == "TcpipSendSlowPath")
            //    {
            //        var tcpIpEvent = new TcpIpEvent
            //        {
            //            EventName = data.EventName,
            //            Timestamp = DateTime.UtcNow
            //        };

            //        // 这里打印所有 TCP/IP 事件的信息
            //        Console.WriteLine($"Event Name: {data.EventName}");
            //        foreach (var payloadName in data.PayloadNames)
            //        {
            //            var payloadValue = data.PayloadByName(payloadName);
            //            var processId = data.ProcessID;
            //            if (payloadValue != null)
            //            {
            //                // 如果是IPv4地址字段，则进行转换
            //                if (payloadName == "SourceIPv4Address" || payloadName == "DestIPv4Address")
            //                {
            //                    // 将整数形式的IP地址转换为点分十进制格式
            //                    var ipAddressString = ConvertToIPAddressString((int)payloadValue);
            //                    Console.WriteLine($" {payloadName}: {ipAddressString}");

            //                    // 检查是否在黑名单中
            //                    if (blacklistIPs.Contains(ipAddressString))
            //                    {
            //                        TerminateProcess(processId);
            //                        Console.WriteLine($"Detected blacklisted IP address: {ipAddressString}");
            //                    }
            //                }
            //                else
            //                {
            //                    Console.WriteLine($" {payloadName}: {payloadValue}");
            //                }
            //            }
            //        }
            //        tcpIpEvent.IsBlacklisted = blacklistIPs.Contains(tcpIpEvent.SourceIpv4Address) || blacklistIPs.Contains(tcpIpEvent.DestIpv4Address);
            //        //IndexDataToElasticsearch(tcpIpEvent, "tcpip-events");
            //    }
            //};


            traceEventSession.Source.Kernel.ProcessStart += data =>
            {
                if (data.ProcessName.ToLower().Contains("nc"))
                {
                    Console.WriteLine($"Debug: Process {data.ProcessName} started with Command Line: {data.CommandLine}");
                    string[] commandParts = data.CommandLine.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (commandParts.Length > 1 && Regex.IsMatch(commandParts[1], @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"))
                    {
                        string ipAddress = commandParts[1];
                        ncProcesses[data.ProcessID] = ipAddress;
                        Console.WriteLine($"[ProcessStart] NC process started with PID: {data.ProcessID}, IP: {ipAddress}");
                    }
                    else
                    {
                        Console.WriteLine("IP address not found or invalid in the command line.");
                    }
                }
            };


            //// 監聽 TCP/IP 連接
            traceEventSession.Source.Dynamic.All += data =>
            {
                if (data.ProviderName == "Microsoft-Windows-TCPIP" && (data.EventName == "TcpipSendSlowPath" || data.EventName == "TcpipReceive"))
                {
                    string destIp = ConvertToIPAddressString((int)data.PayloadByName("DestIPv4Address"));

                    foreach (var kvp in ncProcesses)
                    {
                        if (kvp.Value == destIp && blacklistIPs.Contains(destIp))
                        {
                            Console.WriteLine($"Detected NC process (PID: {kvp.Key}) attempting to connect to blacklisted IP: {destIp}");
                            TerminateProcess(kvp.Key);
                            toRemove.Add(kvp.Key);  // 將要移除的進程 ID 添加到列表
                        }
                    }

                    // 移除已終止的進程
                    foreach (int pid in toRemove)
                    {
                        ncProcesses.Remove(pid);
                    }
                    toRemove.Clear(); // 清理臨時列表以供下次使用
                }
            };

            var etwThread = new Thread(() => traceEventSession.Source.Process());
            etwThread.Start();
        }

        private static void TerminateProcess(int processId)
        {
            try
            {
                Process process = Process.GetProcessById(processId);
                if (!process.HasExited)
                {
                    process.Kill();
                    Console.WriteLine($"Terminated nc process {processId} due to connection attempt to specified IP.");
                    // 這裡不再需要手動移除，因為我們在事件處理器中處理了
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to terminate process {processId}: {ex.Message}");
            }
        }


        private static string ConvertToIPAddressString(int ipAddress)
        {
            return new IPAddress(BitConverter.GetBytes(ipAddress)).ToString();
        }
        //private static string ConvertToIPAddressString(int ipAddress)
        //{
        //    return new IPAddress(BitConverter.GetBytes(ipAddress)).ToString();
        //}
        //private static void TerminateProcess(int processId)
        //{
        //    try
        //    {
        //        Process process = Process.GetProcessById(processId);
        //        if (!process.HasExited) // 检查进程是否仍在运行
        //        {
        //            process.Kill(); // 终止进程
        //            Console.WriteLine($"Process {processId} terminated.");
        //            LogProcessStop(processId, process.ProcessName);
        //        }
        //        else
        //        {
        //            Console.WriteLine($"Process {processId} has already exited.");
        //        }
        //    }
        //    catch (ArgumentException ex)
        //    {
        //        Console.WriteLine($"Error: The process {processId} does not exist. {ex.Message}");
        //    }
        //    catch (InvalidOperationException ex)
        //    {
        //        Console.WriteLine($"Error: The process {processId} has already exited. {ex.Message}");
        //    }
        //    catch (Exception ex)
        //    {
        //        Console.WriteLine($"Error terminating process {processId}: {ex.Message}");
        //    }
        //}

        //private static void LogProcessStop(int processId, string processName)
        //{
        //    Console.WriteLine($"[ProcessStop] Process {processName} (PID: {processId}) has been terminated.");
        //}

        //static void InitializeTCPIP()
        //{
        //    string sessionName = "TcpIpMonitoringSession";
        //    var tcpIpSession = new TraceEventSession(sessionName);

        //    tcpIpSession.EnableProvider("Microsoft-Windows-TCPIP");

        //    tcpIpSession.Source.Dynamic.All += data =>
        //    {
        //        if (data.ProviderName == "Microsoft-Windows-TCPIP" && data.EventName == "TcpipSendSlowPath")
        //        {
        //            Console.WriteLine($"Event Name: {data.EventName}");
        //            foreach (var payloadName in data.PayloadNames)
        //            {
        //                var payloadValue = data.PayloadByName(payloadName);
        //                if (payloadValue != null)
        //                {
        //                    if (payloadName == "SourceIPv4Address" || payloadName == "DestIPv4Address")
        //                    {
        //                        var ipAddressString = ConvertToIPAddressString((int)payloadValue);
        //                        Console.WriteLine($" {payloadName}: {ipAddressString}");

        //                        if (blacklistIPs.Contains(ipAddressString))
        //                        {
        //                            Console.WriteLine($"Detected blacklisted IP address: {ipAddressString}");
        //                        }
        //                    }
        //                    else
        //                    {
        //                        Console.WriteLine($" {payloadName}: {payloadValue}");
        //                    }
        //                }
        //            }
        //        }
        //    };

        //    Console.WriteLine("Listening for TCP/IP events. Press any key to exit.");
        //    tcpIpSession.Source.Process();
        //    Console.ReadKey();
        //}

        static string GetProcessFilePath(int processId)
        {
            try
            {
                var process = Process.GetProcessById(processId);
                return process.MainModule.FileName;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error getting process file path: {ex.Message}");
                return null;
            }
        }

        static void ComputeHashes(string filePath)
        {
            using (var md5 = MD5.Create())
            using (var sha1 = SHA1.Create())
            using (var sha256 = SHA256.Create())
            {
                var fileContent = File.ReadAllBytes(filePath);
                var md5Hash = BitConverter.ToString(md5.ComputeHash(fileContent)).Replace("-", "");
                var sha1Hash = BitConverter.ToString(sha1.ComputeHash(fileContent)).Replace("-", "");
                var sha256Hash = BitConverter.ToString(sha256.ComputeHash(fileContent)).Replace("-", "");

                Console.WriteLine($"MD5: {md5Hash}");
                Console.WriteLine($"SHA1: {sha1Hash}");
                Console.WriteLine($"SHA256: {sha256Hash}");
            }
        }

        static string BytesToIPAddressString(byte[] bytes)
        {
            if (bytes == null)
            {
                return "Unavailable";
            }

            try
            {
                IPAddress ip = new IPAddress(bytes);
                return ip.ToString();
            }
            catch
            {
                return "Invalid IP Address";
            }
        }

        static void InitializeFileSystemWatcher(string path, string filter, string notifyFilter)
        {
            watcher = new FileSystemWatcher
            {
                Path = path,
                Filter = filter,
                NotifyFilter = ParseNotifyFilters(notifyFilter)
            };

            watcher.Changed += OnChanged;
            watcher.Created += OnCreated;
            watcher.Deleted += OnDeleted;
            watcher.Renamed += OnRenamed;
            watcher.Error += OnError;

            watcher.EnableRaisingEvents = true;
        }

        static NotifyFilters ParseNotifyFilters(string notifyFilter)
        {
            NotifyFilters filters = NotifyFilters.LastAccess;
            string[] tokens = notifyFilter.Split(',');
            foreach (var token in tokens)
            {
                if (Enum.TryParse(token.Trim(), out NotifyFilters result))
                {
                    filters |= result;
                }
            }
            return filters;
        }

        static void OnProcessStarted(ProcessTraceData data)
        {
            Console.WriteLine($"[ProcessStart] {data.ProcessName} (PID: {data.ProcessID}) started. Provider: {data.ProviderName}, Event: ProcessStart, Command Line: {data.CommandLine}\n");
        }

        static void OnProcessStopped(ProcessTraceData data)
        {
            Console.WriteLine($"[ProcessStop] {data.ProcessName} (PID: {data.ProcessID}) stopped. Provider: {data.ProviderName}, Event: ProcessStop, Command Line: {data.CommandLine}\n");
        }

        private static void OnChanged(object source, FileSystemEventArgs e)
        {
            Console.WriteLine($"[FileChanged] {e.FullPath}");
            //var fileSystemEvent = new { EventType = e.ChangeType.ToString(), FilePath = e.FullPath, Timestamp = DateTime.UtcNow };
            //IndexDataToElasticsearch(fileSystemEvent, "file-system-events");
        }

        private static void OnCreated(object source, FileSystemEventArgs e)
        {
            Console.WriteLine($"[FileCreated] {e.FullPath}");
            //var fileSystemEvent = new { EventType = e.ChangeType.ToString(), FilePath = e.FullPath, Timestamp = DateTime.UtcNow };
            //IndexDataToElasticsearch(fileSystemEvent, "file-system-events");
        }

        private static void OnDeleted(object source, FileSystemEventArgs e)
        {
            Console.WriteLine($"[FileDeleted] {e.FullPath}");
            //var fileSystemEvent = new { EventType = e.ChangeType.ToString(), FilePath = e.FullPath, Timestamp = DateTime.UtcNow };
            //IndexDataToElasticsearch(fileSystemEvent, "file-system-events");
        }

        private static void OnRenamed(object source, RenamedEventArgs e)
        {
            Console.WriteLine($"[FileRenamed] from {e.OldFullPath} to {e.FullPath}");
            //var fileSystemEvent = new { EventType = e.ChangeType.ToString(), FilePath = e.FullPath, Timestamp = DateTime.UtcNow };
            //IndexDataToElasticsearch(fileSystemEvent, "file-system-events");
        }

        private static void OnError(object source, ErrorEventArgs e)
        {
            Console.WriteLine($"[WatcherError] {e.GetException().Message}");
            //var errorEvent = new { EventType = "Error", Message = e.GetException().Message, Timestamp = DateTime.UtcNow };
            //IndexDataToElasticsearch(errorEvent, "file-system-events");
        }

        //private static void IndexDataToElasticsearch<T>(T data, string indexName) where T : class
        //{
        //    if (!(client.Indices.Exists(indexName).Exists))
        //    {
        //        var createIndexResponse = client.Indices.Create(indexName, c => c.Map<T>(m => m.AutoMap())
        //            .Settings(s => s
        //                .NumberOfShards(1)
        //                .NumberOfReplicas(1)));
        //    }

        //    var response = client.Index(data, idx => idx.Index(indexName));
        //    if (!response.IsValid)
        //    {
        //        Console.WriteLine($"Error indexing data to Elasticsearch: {response.OriginalException.Message}");
        //    }
        //}
    }
}

//using Microsoft.Diagnostics.Tracing;
//using Microsoft.Diagnostics.Tracing.Parsers;
//using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
//using Microsoft.Diagnostics.Tracing.Session;
//using System;
//using System.Collections.Generic;
//using System.IO;
//using System.Linq;
//using System.Text.RegularExpressions;
//using System.Threading;
//using System.Xml.Linq;
//using System.Net;
////using Nest;
//using System.Diagnostics;
//using System.Security.Cryptography;
//using System.Text;

//namespace ConsoleApp1
//{
//    //public class ProcessEvent
//    //{
//    //    public string ProcessName { get; set; }
//    //    public int ProcessId { get; set; }
//    //    public string CommandLine { get; set; }
//    //    public DateTime Timestamp { get; set; }
//    //    public string EventType { get; set; }
//    //}

//    //public class TcpIpEvent
//    //{
//    //    public string EventName { get; set; }
//    //    public string SourceIPv4Address { get; set; }
//    //    public string DestIPv4Address { get; set; }
//    //    public bool IsBlacklisted { get; set; }
//    //    public DateTime Timestamp { get; set; }
//    //}

//    class Program
//    {
//        static FileSystemWatcher watcher;
//        static TraceEventSession traceEventSession;
//        static HashSet<string> monitoredProcesses;
//        static HashSet<string> blacklistIPs;
//        //private static ElasticClient client;



//        static void Main(string[] args)
//        {
//            //var uri = new Uri("http://localhost:9200");

//            //var settings = new ConnectionSettings(uri);

//            //client = new ElasticClient(settings);
//            //var response = client.Ping();
//            //if (response.IsValid)
//            //{
//            //    Console.WriteLine("Successfully connected to Elasticsearch.");
//            //}
//            //else
//            //{
//            //    Console.WriteLine("Failed to connect to Elasticsearch.");
//            //}

//            //if (!(TraceEventSession.IsElevated() ?? false))
//            //{
//            //    Console.WriteLine("Please run me as administrator");
//            //    return;
//            //}

//            // 讀取 XML 配置文件
//            //var config = XDocument.Load("etwrole.xml");
//            var config = XDocument.Load(@"C:\Users\frank\OneDrive\桌面\etw\etwrole.xml");
//            var watcherConfig = config.Element("Configuration").Element("FileSystemWatcherConfig");
//            var processMonitorConfig = config.Element("Configuration").Element("ProcessMonitorConfig");
//            var blacklistrConfig = config.Element("Configuration").Element("blacklist");


//            monitoredProcesses = new HashSet<string>();
//            blacklistIPs = new HashSet<string>();

//            if (processMonitorConfig != null)
//            {
//                foreach (var name in processMonitorConfig.Elements("Name"))
//                {
//                    monitoredProcesses.Add(name.Value);
//                    Console.WriteLine("Added to monitoring: " + name.Value);
//                }
//            }

//            foreach (var ip in config.Element("Configuration").Element("Blacklists").Elements("IP"))
//            {
//                blacklistIPs.Add(ip.Value);
//            }

//            //ExecuteNetshCommand("trace start capture=yes");


//            // 初始化 ETW
//            InitializeETW();
//            //InitializeTCPIP();

//            // 使用配置文件初始化 FileSystemWatcher
//            InitializeFileSystemWatcher(
//                watcherConfig.Element("Path").Value,
//                watcherConfig.Element("Filter").Value,
//                watcherConfig.Element("NotifyFilter").Value
//            );

//            Console.WriteLine("Monitoring started. Press 'Enter' to quit.");
//            Console.ReadLine();

//            watcher.EnableRaisingEvents = false;
//            watcher.Dispose();
//            traceEventSession.Dispose();
//            //ExecuteNetshCommand("trace stop");

//        }

//        ////測試用
//        //private static void InitializeETW()
//        //{
//        //    traceEventSession = new TraceEventSession("MyETWSession");
//        //    traceEventSession.EnableKernelProvider(
//        //        KernelTraceEventParser.Keywords.Process |
//        //        KernelTraceEventParser.Keywords.ImageLoad);
//        //    traceEventSession.Source.Kernel.ProcessStart += data =>
//        //    {
//        //        OnProcessStarted(data);
//        //    };
//        //    traceEventSession.Source.Kernel.ProcessStop += data =>
//        //    {
//        //        OnProcessStopped(data);
//        //    };
//        //    //traceEventSession.Source.Kernel.ImageLoad += data =>
//        //    //{
//        //    //    OnImageLoaded(data);
//        //    //};

//        //    var etwThread = new Thread(() => traceEventSession.Source.Process());
//        //    etwThread.Start();
//        //}



//        static void InitializeETW()
//        {

//            traceEventSession = new TraceEventSession("MyETWSession");
//            traceEventSession.EnableKernelProvider(
//                    KernelTraceEventParser.Keywords.NetworkTCPIP | 
//                    KernelTraceEventParser.Keywords.Process |      
//                    KernelTraceEventParser.Keywords.ImageLoad);
//            traceEventSession.EnableProvider("Microsoft-Windows-TCPIP");

//            //ProcessStart
//            traceEventSession.Source.Kernel.ProcessStart += data =>
//            {
//                //var processEvent = new ProcessEvent
//                //{
//                //    ProcessName = data.ProcessName,
//                //    ProcessId = data.ProcessID,
//                //    CommandLine = data.CommandLine,
//                //    Timestamp = DateTime.UtcNow,
//                //    EventType = "ProcessStart"
//                //};

//                OnProcessStarted(data);
//                //IndexDataToElasticsearch(processEvent, "etw-events");
//                if (data.ProcessName.ToLower().Contains("nc") || data.ProcessName.Contains("VirtualBoxVM"))
//                {
//                    Console.WriteLine($"NC Process started: {data.ProcessName} (PID: {data.ProcessID})");


//                    string filePath = GetProcessFilePath(data.ProcessID);
//                    if (!string.IsNullOrEmpty(filePath))
//                    {
//                        Console.WriteLine($"File Path: {filePath}");
//                        ComputeHashes(filePath);
//                    }
//                }
//            };

//            //ProcessStop
//            //traceEventSession.Source.Kernel.ProcessStop += data =>
//            //{
//            //    var processEvent = new ProcessEvent
//            //    {
//            //        ProcessName = data.ProcessName,
//            //        ProcessId = data.ProcessID,
//            //        CommandLine = data.CommandLine,
//            //        Timestamp = DateTime.UtcNow,
//            //        EventType = "ProcessStop"
//            //    };
//            //    OnProcessStopped(data);
//            //    IndexDataToElasticsearch(processEvent, "etw-events");
//            //};

//            ////TCPIP
//            traceEventSession.Source.Dynamic.All += data =>
//            {

//                if (data.ProviderName == "Microsoft-Windows-TCPIP" && data.EventName == "TcpipSendSlowPath")
//                {
//                    //var tcpIpEvent = new TcpIpEvent
//                    //{
//                    //    EventName = data.EventName,
//                    //    Timestamp = DateTime.UtcNow
//                    //};

//                    // 这里打印所有 TCP/IP 事件的信息
//                    Console.WriteLine($"Event Name: {data.EventName}");
//                    foreach (var payloadName in data.PayloadNames)
//                    {
//                        var payloadValue = data.PayloadByName(payloadName);
//                        var processId = data.ProcessID;
//                        if (payloadValue != null)
//                        {
//                            // 如果是IPv4地址字段，则进行转换
//                            if (payloadName == "SourceIPv4Address" || payloadName == "DestIPv4Address")
//                            {
//                                // 将整数形式的IP地址转换为点分十进制格式
//                                var ipAddressString = ConvertToIPAddressString((int)payloadValue);
//                                Console.WriteLine($" {payloadName}: {ipAddressString}");

//                                // 检查是否在黑名单中
//                                if (blacklistIPs.Contains(ipAddressString))
//                                {
//                                    //new
//                                    TerminateProcess(processId);
//                                    Console.WriteLine($"Detected blacklisted IP address: {ipAddressString}");
//                                }
//                            }
//                            else
//                            {
//                                Console.WriteLine($" {payloadName}: {payloadValue}");
//                            }
//                        }
//                    }
//                    //tcpIpEvent.IsBlacklisted = blacklistIPs.Contains(tcpIpEvent.SourceIPv4Address) || blacklistIPs.Contains(tcpIpEvent.DestIPv4Address);
//                    //IndexDataToElasticsearch(tcpIpEvent, "tcpip-events");
//                }
//            };

//            var etwThread = new Thread(() => traceEventSession.Source.Process());
//            etwThread.Start();
//        }

//        private static void TerminateProcess(int processId)
//        {
//            try
//            {
//                Process process = Process.GetProcessById(processId);
//                string processName = process.ProcessName.ToLower();

//                // 检查进程名称是否为"nc"
//                if (!process.HasExited && processName.Contains("nc"))
//                {
//                    process.Kill();
//                    Console.WriteLine($"Terminated 'nc' process with ID {processId} attempting to connect to a blacklisted IP.");
//                }
//                else if (!process.HasExited)
//                {
//                    Console.WriteLine($"Process {processId} ({processName}) is not an 'nc' process, skipping termination.");
//                }
//            }
//            catch (ArgumentException ex)
//            {
//                Console.WriteLine($"Error: The process {processId} does not exist. {ex.Message}");
//            }
//            catch (InvalidOperationException ex)
//            {
//                Console.WriteLine($"Error: The process {processId} has already exited. {ex.Message}");
//            }
//            catch (Exception ex)
//            {
//                Console.WriteLine($"Failed to terminate process {processId}: {ex.Message}");
//            }
//        }


//        //private static void TerminateProcess(int processId)
//        //{
//        //    try
//        //    {
//        //        Process process = Process.GetProcessById(processId);
//        //        if (!process.HasExited)
//        //        {
//        //            process.Kill();
//        //            Console.WriteLine($"Terminated process {processId} attempting to connect to a blacklisted IP.");
//        //        }
//        //    }
//        //    catch (Exception ex)
//        //    {
//        //        Console.WriteLine($"Failed to terminate process {processId}: {ex.Message}");
//        //    }
//        //}

//        // 将字节数组转换为IP地址字符串
//        private static string ConvertIPAddress(object ip)
//        {
//            if (ip == null) return "0.0.0.0";
//            byte[] bytes = (byte[])ip;
//            return new IPAddress(bytes).ToString();
//        }

//        ////new
//        //private static void TerminateProcess(int processId)
//        //{
//        //    try
//        //    {
//        //        Process process = Process.GetProcessById(processId);
//        //        if (!process.HasExited) // 检查进程是否仍在运行
//        //        {
//        //            process.Kill(); // 终止进程
//        //            Console.WriteLine($"Process {processId} terminated.");
//        //            // 在这里记录进程终止信息
//        //            LogProcessStop(processId, process.ProcessName);
//        //        }
//        //        else
//        //        {
//        //            Console.WriteLine($"Process {processId} has already exited.");
//        //        }
//        //    }
//        //    catch (ArgumentException ex)
//        //    {
//        //        // 指定的进程不存在
//        //        Console.WriteLine($"Error: The process {processId} does not exist. {ex.Message}");
//        //    }
//        //    catch (InvalidOperationException ex)
//        //    {
//        //        // 进程已经退出
//        //        Console.WriteLine($"Error: The process {processId} has already exited. {ex.Message}");
//        //    }
//        //    catch (Exception ex)
//        //    {
//        //        // 其他错误
//        //        Console.WriteLine($"Error terminating process {processId}: {ex.Message}");
//        //    }
//        //}


//        //// 用于记录进程停止信息的方法
//        //private static void LogProcessStop(int processId, string processName)
//        //{
//        //    Console.WriteLine($"[ProcessStop] Process {processName} (PID: {processId}) has been terminated.");
//        //}



//        ////全印
//        //static void InitializeTCPIP()
//        //{
//        //    // 创建一个 ETW 会话
//        //    string session = "TcpIpMonitoringSession";

//        //    // 监听 Microsoft-Windows-TCPIP 提供者的事件
//        //    session.EnableProvider("Microsoft-Windows-TCPIP");

//        //    // 事件处理
//        //    session.Source.Dynamic.All += data =>
//        //    {
//        //        if (data.ProviderName == "Microsoft-Windows-TCPIP" && data.EventName == "TcpipSendSlowPath")
//        //        {
//        //            // 这里打印所有 TCP/IP 事件的信息
//        //            Console.WriteLine($"Event Name: {data.EventName}");
//        //            foreach (var payloadName in data.PayloadNames)
//        //            {
//        //                var payloadValue = data.PayloadByName(payloadName);
//        //                if (payloadValue != null)
//        //                {
//        //                    // 如果是IPv4地址字段，则进行转换
//        //                    if (payloadName == "SourceIPv4Address" || payloadName == "DestIPv4Address")
//        //                    {
//        //                        // 将整数形式的IP地址转换为点分十进制格式
//        //                        var ipAddressString = ConvertToIPAddressString((int)payloadValue);
//        //                        Console.WriteLine($" {payloadName}: {ipAddressString}");

//        //                        // 检查是否在黑名单中
//        //                        if (blacklistIPs.Contains(ipAddressString))
//        //                        {
//        //                            Console.WriteLine($"Detected blacklisted IP address: {ipAddressString}");
//        //                        }
//        //                    }
//        //                    else
//        //                    {
//        //                        Console.WriteLine($" {payloadName}: {payloadValue}");
//        //                    }
//        //                }
//        //            }
//        //        }

//        //    };

//        //    Console.WriteLine("Listening for TCP/IP events. Press any key to exit.");
//        //    session.Source.Process();
//        //    Console.ReadKey();

//        //}


//        static string GetProcessFilePath(int processId)
//        {
//            try
//            {
//                var process = Process.GetProcessById(processId);
//                return process.MainModule.FileName;
//            }
//            catch (Exception ex)
//            {
//                Console.WriteLine($"Error getting process file path: {ex.Message}");
//                return null;
//            }
//        }

//        static void ComputeHashes(string filePath)
//        {
//            using (var md5 = MD5.Create())
//            using (var sha1 = SHA1.Create())
//            using (var sha256 = SHA256.Create())
//            {
//                var fileContent = File.ReadAllBytes(filePath);
//                var md5Hash = BitConverter.ToString(md5.ComputeHash(fileContent)).Replace("-", "");
//                var sha1Hash = BitConverter.ToString(sha1.ComputeHash(fileContent)).Replace("-", "");
//                var sha256Hash = BitConverter.ToString(sha256.ComputeHash(fileContent)).Replace("-", "");

//                Console.WriteLine($"MD5: {md5Hash}");
//                Console.WriteLine($"SHA1: {sha1Hash}");
//                Console.WriteLine($"SHA256: {sha256Hash}");
//            }
//        }



//        // 将整数形式的IPv4地址转换为点分十进制格式
//        static string ConvertToIPAddressString(int ipAddress)
//        {
//            return new IPAddress(BitConverter.GetBytes(ipAddress)).ToString();
//        }

//        static string BytesToIPAddressString(byte[] bytes)
//        {
//            if (bytes == null)
//            {
//                return "Unavailable";
//            }

//            try
//            {
//                IPAddress ip = new IPAddress(bytes);
//                return ip.ToString();
//            }
//            catch
//            {
//                return "Invalid IP Address";
//            }
//        }


//        static void InitializeFileSystemWatcher(string path, string filter, string notifyFilter)
//        {
//            watcher = new FileSystemWatcher
//            {
//                Path = path,
//                Filter = filter,
//                NotifyFilter = ParseNotifyFilters(notifyFilter)
//            };

//            watcher.Changed += OnChanged;
//            watcher.Created += OnCreated;
//            watcher.Deleted += OnDeleted;
//            watcher.Renamed += OnRenamed;
//            watcher.Error += OnError;

//            watcher.EnableRaisingEvents = true;
//        }

//        static NotifyFilters ParseNotifyFilters(string notifyFilter)
//        {
//            NotifyFilters filters = NotifyFilters.LastAccess;
//            string[] tokens = notifyFilter.Split(',');
//            foreach (var token in tokens)
//            {
//                if (Enum.TryParse(token.Trim(), out NotifyFilters result))
//                {
//                    filters |= result;
//                }
//            }
//            return filters;
//        }


//        static void OnProcessStarted(ProcessTraceData data)
//        {
//            Console.WriteLine($"[ProcessStart] {data.ProcessName} (PID: {data.ProcessID}) started. Provider: {data.ProviderName}, Event: ProcessStart, Command Line: {data.CommandLine}\n");
//        }

//        static void OnProcessStopped(ProcessTraceData data)
//        {

//            Console.WriteLine($"[ProcessStop] {data.ProcessName} (PID: {data.ProcessID}) stopped. Provider: {data.ProviderName}, Event: ProcessStop, Command Line: {data.CommandLine}\n");

//        }


//        //private static void OnImageLoaded(ImageLoadTraceData data)
//        //{
//        //    Console.WriteLine($"[ImageLoad] {data.FileName} loaded by {data.ProcessName} with PID {data.ProcessID}Provider: {data.ProviderName}, Event: ImageLoad");
//        //}
//        private static void OnChanged(object source, FileSystemEventArgs e)
//        {
//            Console.WriteLine($"[FileChanged] {e.FullPath}");
//            //var fileSystemEvent = new { EventType = e.ChangeType.ToString(), FilePath = e.FullPath, Timestamp = DateTime.UtcNow };
//            //IndexDataToElasticsearch(fileSystemEvent, "file-system-events");
//        }

//        private static void OnCreated(object source, FileSystemEventArgs e)
//        {
//            Console.WriteLine($"[FileCreated] {e.FullPath}");
//            //var fileSystemEvent = new { EventType = e.ChangeType.ToString(), FilePath = e.FullPath, Timestamp = DateTime.UtcNow };
//            //IndexDataToElasticsearch(fileSystemEvent, "file-system-events");
//        }

//        private static void OnDeleted(object source, FileSystemEventArgs e)
//        {
//            Console.WriteLine($"[FileDeleted] {e.FullPath}");
//            //var fileSystemEvent = new { EventType = e.ChangeType.ToString(), FilePath = e.FullPath, Timestamp = DateTime.UtcNow };
//            //IndexDataToElasticsearch(fileSystemEvent, "file-system-events");
//        }

//        private static void OnRenamed(object source, RenamedEventArgs e)
//        {
//            Console.WriteLine($"[FileRenamed] from {e.OldFullPath} to {e.FullPath}");
//            //var fileSystemEvent = new { EventType = e.ChangeType.ToString(), FilePath = e.FullPath, Timestamp = DateTime.UtcNow };
//            //IndexDataToElasticsearch(fileSystemEvent, "file-system-events");
//        }
//        private static void OnError(object source, ErrorEventArgs e)
//        {
//            Console.WriteLine($"[WatcherError] {e.GetException().Message}");
//            //var errorEvent = new { EventType = "Error", Message = e.GetException().Message, Timestamp = DateTime.UtcNow };
//            //IndexDataToElasticsearch(errorEvent, "file-system-events");
//        }

//        //private static void IndexDataToElasticsearch<T>(T data, string indexname) where T : class
//        //{
//        //    if (!(client.Indices.Exists(indexname).Exists))
//        //    {
//        //        var createIndexResponse = client.Indices.Create(indexname, c => c.Map<T>(m => m.AutoMap()) // 自动映射T类型的属性
//        //        .Settings(s => s
//        //        .NumberOfShards(1) // 设置分片数量
//        //        .NumberOfReplicas(1))); // 设置副本数量

//        //    }

//        //    var response = client.Index(data, idx => idx.Index(indexname));
//        //    if (!response.IsValid)
//        //    {
//        //        Console.WriteLine($"Error indexing data to Elasticsearch: {response.OriginalException.Message}");
//        //    }

//        //}
//    }
//}





