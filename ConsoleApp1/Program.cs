using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using System.Xml.XPath;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace SystemMonitoring
{

    using System;
    using System.Threading.Tasks;


        class Program
        {
            static async Task Main(string[] args)
            {
                try
                {
                    Console.WriteLine("Starting System Monitoring...");

                    // 配置文件路徑
                    string configPath = "C:\\Users\\frank\\OneDrive\\桌面\\etw\\etwrole.xml"; // 請確保這個路徑正確
                    if (args.Length > 0)
                    {
                        configPath = args[0];
                    }

                    // 創建並啟動監控系統
                    using (var monitor = new SystemMonitor(configPath))
                    {
                        Console.WriteLine("Monitoring system initialized.");
                        Console.WriteLine("Press Ctrl+C to stop monitoring.");

                        // 設置 Console.CancelKeyPress 事件處理
                        var tcs = new TaskCompletionSource<bool>();
                        Console.CancelKeyPress += (s, e) =>
                        {
                            e.Cancel = true; // 防止立即終止
                            tcs.SetResult(true);
                            Console.WriteLine("\nShutting down...");
                        };

                        // 啟動監控
                        var monitoringTask = monitor.StartMonitoring();

                        // 等待 Ctrl+C 或其他終止信號
                        await Task.WhenAny(monitoringTask, tcs.Task);
                    }

                    Console.WriteLine("Monitoring stopped successfully.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Fatal error: {ex.Message}");
                    Console.WriteLine(ex.StackTrace);
                    Environment.Exit(1);
                }
            }
        }
    

    public class MonitoringConfiguration
    {
        public string WatchPath { get; set; }
        public string WatchFilter { get; set; }
        public string NotifyFilter { get; set; }
        public HashSet<string> MonitoredProcesses { get; set; }
        public HashSet<string> BlacklistedIPs { get; set; }
        public Dictionary<string, string> KnownFileHashes { get; set; }
    }

    public class FileHashInfo
    {
        public string FilePath { get; set; }
        public string MD5Hash { get; set; }
        public string SHA1Hash { get; set; }
        public string SHA256Hash { get; set; }
        public DateTime LastChecked { get; set; }
    }

    public class SystemMonitor : IDisposable
    {
        private readonly MonitoringConfiguration _config;
        private readonly FileSystemWatcher _watcher;
        private readonly TraceEventSession _traceSession;
        private readonly Dictionary<int, string> _processNames;
        private readonly Dictionary<string, FileHashInfo> _fileHashes;
        private readonly CancellationTokenSource _cancellationTokenSource;
        private bool _disposed;

        public SystemMonitor(string configPath)
        {
            _config = LoadConfiguration(configPath);
            _processNames = new Dictionary<int, string>();
            _fileHashes = new Dictionary<string, FileHashInfo>();
            _cancellationTokenSource = new CancellationTokenSource();

            // Initialize components
            _watcher = InitializeFileSystemWatcher();
            _traceSession = InitializeETWSession();
        }

        private MonitoringConfiguration LoadConfiguration(string path)
        {
            var config = XDocument.Load(path);
            return new MonitoringConfiguration
            {
                WatchPath = config.XPathSelectElement("//FileSystemWatcherConfig/Path")?.Value,
                WatchFilter = config.XPathSelectElement("//FileSystemWatcherConfig/Filter")?.Value,
                NotifyFilter = config.XPathSelectElement("//FileSystemWatcherConfig/NotifyFilter")?.Value,
                MonitoredProcesses = new HashSet<string>(
                    config.XPathSelectElements("//ProcessMonitorConfig/Name").Select(x => x.Value)),
                BlacklistedIPs = new HashSet<string>(
                    config.XPathSelectElements("//Blacklists/IP").Select(x => x.Value)),
                KnownFileHashes = new Dictionary<string, string>()
            };
        }

        private FileSystemWatcher InitializeFileSystemWatcher()
        {
            var watcher = new FileSystemWatcher
            {
                Path = _config.WatchPath,
                Filter = _config.WatchFilter,
                NotifyFilter = ParseNotifyFilters(_config.NotifyFilter)
            };

            watcher.Changed += OnFileChanged;
            watcher.Created += OnFileCreated;
            watcher.Deleted += OnFileDeleted;
            watcher.Renamed += OnFileRenamed;
            watcher.Error += OnWatcherError;

            return watcher;
        }

        private TraceEventSession InitializeETWSession()
        {
            if (!(TraceEventSession.IsElevated() ?? false))
            {
                throw new UnauthorizedAccessException("This application requires administrator privileges.");
            }

            var session = new TraceEventSession("SystemMonitorSession");
            session.EnableKernelProvider(
                KernelTraceEventParser.Keywords.NetworkTCPIP |
                KernelTraceEventParser.Keywords.Process |
                KernelTraceEventParser.Keywords.ImageLoad
            );
            session.EnableProvider("Microsoft-Windows-TCPIP");

            // Set up event handlers
            session.Source.Kernel.ProcessStart += OnProcessStarted;
            session.Source.Kernel.ProcessStop += OnProcessStopped;
            session.Source.Dynamic.All += OnTcpIpEvent;

            return session;
        }

        public async Task StartMonitoring()
        {
            _watcher.EnableRaisingEvents = true;

            // Start ETW processing
            await Task.Run(() => _traceSession.Source.Process());
        }

        static void ComputeHashes(string filePath)
        {
            try
            {
                // 使用 FileShare.Read 允許其他程序同時訪問文件
                using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var md5 = MD5.Create())
                using (var sha1 = SHA1.Create())
                using (var sha256 = SHA256.Create())
                {
                    Console.WriteLine($"[Hash Calculation Start] File: {filePath}");

                    // 計算 MD5
                    byte[] md5Hash = md5.ComputeHash(stream);
                    Console.WriteLine($"MD5: {BitConverter.ToString(md5Hash).Replace("-", "")}");

                    // 計算 SHA1
                    stream.Position = 0; 
                    byte[] sha1Hash = sha1.ComputeHash(stream);
                    Console.WriteLine($"SHA1: {BitConverter.ToString(sha1Hash).Replace("-", "")}");

                    // 計算 SHA256
                    stream.Position = 0; 
                    byte[] sha256Hash = sha256.ComputeHash(stream);
                    Console.WriteLine($"SHA256: {BitConverter.ToString(sha256Hash).Replace("-", "")}");

                    Console.WriteLine("[Hash Calculation Complete]");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Error] Failed to compute hashes for {filePath}: {ex.Message}");
            }
        }

        // 增加一個異步版本的哈希計算方法，用於處理大文件
        static async Task ComputeHashesAsync(string filePath)
        {
            try
            {
                using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var md5 = MD5.Create())
                using (var sha1 = SHA1.Create())
                using (var sha256 = SHA256.Create())
                {
                    Console.WriteLine($"[Hash Calculation Start] File: {filePath}");

                    // 使用緩衝區進行異步讀取
                    var buffer = new byte[8192];
                    int bytesRead;
                    while ((bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                    {
                        md5.TransformBlock(buffer, 0, bytesRead, null, 0);
                        sha1.TransformBlock(buffer, 0, bytesRead, null, 0);
                        sha256.TransformBlock(buffer, 0, bytesRead, null, 0);
                    }

                    // 完成哈希計算
                    md5.TransformFinalBlock(buffer, 0, 0);
                    sha1.TransformFinalBlock(buffer, 0, 0);
                    sha256.TransformFinalBlock(buffer, 0, 0);

                    // 輸出結果
                    Console.WriteLine($"MD5: {BitConverter.ToString(md5.Hash).Replace("-", "")}");
                    Console.WriteLine($"SHA1: {BitConverter.ToString(sha1.Hash).Replace("-", "")}");
                    Console.WriteLine($"SHA256: {BitConverter.ToString(sha256.Hash).Replace("-", "")}");

                    Console.WriteLine("[Hash Calculation Complete]");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Error] Failed to compute hashes for {filePath}: {ex.Message}");
            }
        }



        private void OnProcessStarted(ProcessTraceData data)
        {
            if (_config.MonitoredProcesses.Contains(data.ProcessName, StringComparer.OrdinalIgnoreCase))
            {
                try
                {
                    Console.WriteLine($"[ProcessStart] {data.ProcessName} (PID: {data.ProcessID}) 已啟動。");
                    Console.WriteLine($"命令列: {data.CommandLine}");

                    string filePath = ExtractExecutablePath(data.CommandLine);

                    if (!string.IsNullOrEmpty(filePath) && File.Exists(filePath))
                    {
                        Console.WriteLine($"[ProcessFile] {filePath}");
                        // 使用Task來非同步計算雜湊值
                        Task.Run(() => ComputeHashes(filePath))
                            .ContinueWith(t => {
                                if (t.Exception != null)
                                {
                                    Console.WriteLine($"[Error] 計算雜湊值時發生錯誤: {t.Exception.InnerException?.Message}");
                                }
                            }, TaskContinuationOptions.OnlyOnFaulted);
                    }
                    else
                    {
                        Console.WriteLine($"[警告] 無法取得或驗證程序 {data.ProcessName} 的檔案路徑");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Error] 處理程序啟動事件時發生錯誤: {ex.Message}");
                }
            }
        }
        private string ExtractExecutablePath(string commandLine)
        {
            try
            {
                if (string.IsNullOrEmpty(commandLine))
                    return null;

                // 如果命令行以引號開始，尋找配對的結束引號
                if (commandLine.StartsWith("\""))
                {
                    int endQuote = commandLine.IndexOf("\"", 1);
                    if (endQuote > 0)
                    {
                        return commandLine.Substring(1, endQuote - 1);
                    }
                }

                // 如果沒有引號，取第一個空格之前的內容
                int spaceIndex = commandLine.IndexOf(" ");
                if (spaceIndex > 0)
                {
                    return commandLine.Substring(0, spaceIndex);
                }

                // 如果沒有空格，返回整個命令行
                return commandLine;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Error] 提取可執行文件路徑時發生錯誤: {ex.Message}");
                return null;
            }
        }
        private void OnProcessStopped(ProcessTraceData data)
        {
            Console.WriteLine($"[ProcessStop] {data.ProcessName} (PID: {data.ProcessID})");
            _processNames.Remove(data.ProcessID);
        }

        //private void OnTcpIpEvent(TraceEvent data)
        //{
        //    if (data.ProviderName == "Microsoft-Windows-TCPIP" && data.EventName == "TcpipSendSlowPath")
        //    {
        //        var sourceIp = ConvertToIPAddress((int)data.PayloadByName("SourceIPv4Address"));
        //        var destIp = ConvertToIPAddress((int)data.PayloadByName("DestIPv4Address"));

        //        if (_config.BlacklistedIPs.Contains(sourceIp) || _config.BlacklistedIPs.Contains(destIp))
        //        {
        //            Console.WriteLine($"[BlacklistedIP] Process {data.ProcessID} attempting to connect to {destIp}");
        //            TerminateProcess(data.ProcessID);
        //        }
        //    }
        //}

        private void OnTcpIpEvent(TraceEvent data)
        {
            try
            {
                // 增加更多的事件類型監控
                if (data.ProviderName == "Microsoft-Windows-TCPIP" && data.EventName == "TcpipSendSlowPath")
                {
                    // 檢查各種 TCP/IP 相關事件
                    switch (data.EventName)
                    {
                        case "TcpipSendSlowPath":
                        case "TcpConnectionAttempt":
                        case "TcpPortOpened":
                        case "TcpConnect":
                        case "TcpDisconnect":
                            var sourceIp = data.PayloadByName("SourceIPv4Address") != null
                                ? ConvertToIPAddress((int)data.PayloadByName("SourceIPv4Address"))
                                : null;
                            var destIp = data.PayloadByName("DestIPv4Address") != null
                                ? ConvertToIPAddress((int)data.PayloadByName("DestIPv4Address"))
                                : null;

                            if (sourceIp != null || destIp != null)
                            {
                                Console.WriteLine($"[TCP Event] {data.EventName}");
                                Console.WriteLine($"Source IP: {sourceIp ?? "N/A"}");
                                Console.WriteLine($"Destination IP: {destIp ?? "N/A"}");
                                Console.WriteLine($"Process ID: {data.ProcessID}");

                                // 檢查是否為黑名單 IP
                                if ((sourceIp != null && _config.BlacklistedIPs.Contains(sourceIp)) ||
                                    (destIp != null && _config.BlacklistedIPs.Contains(destIp)))
                                {
                                    Console.WriteLine($"[BlacklistedIP] 進程 {data.ProcessID} 嘗試連接到黑名單 IP");
                                    TerminateProcess(data.ProcessID);
                                }
                            }
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Error] 處理 TCP/IP 事件時發生錯誤: {ex.Message}");
            }
        }

        private void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            Console.WriteLine($"[FileChanged] {e.FullPath}");
            //_ = CheckFileHash(e.FullPath);
        }
        private static void OnFileCreated(object source, FileSystemEventArgs e)
        {
            Console.WriteLine($"[FileCreated] {e.FullPath}");
        }

        private static void OnFileDeleted(object source, FileSystemEventArgs e)
        {
            Console.WriteLine($"[FileDeleted] {e.FullPath}");
        }

        private static void OnFileRenamed(object source, RenamedEventArgs e)
        {
            Console.WriteLine($"[FileRenamed] from {e.OldFullPath} to {e.FullPath}");

        }

        private static void OnWatcherError(object source, ErrorEventArgs e)
        {
            Console.WriteLine($"[WatcherError] {e.GetException().Message}");
        }

        static string GetProcessFilePath(int processId)
        {
            try
            {
                var process = Process.GetProcessById(processId);
                return process.MainModule?.FileName;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error getting process file path: {ex.Message}");
                return null;
            }
        }


        private static string ConvertToIPAddress(int ipAddress)
        {
            return new IPAddress(BitConverter.GetBytes(ipAddress)).ToString();
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
        // 其他事件處理方法...



        public void Dispose()
        {
            if (!_disposed)
            {
                _cancellationTokenSource.Cancel();
                _watcher.Dispose();
                _traceSession.Dispose();
                _disposed = true;
            }
        }

        // 輔助方法...
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
//    public class ProcessEvent
//    {
//        public string ProcessName { get; set; }
//        public int ProcessId { get; set; }
//        public string CommandLine { get; set; }
//        public DateTime Timestamp { get; set; }
//        public string EventType { get; set; }
//    }

//    public class TcpIpEvent
//    {

//        public string EventName { get; set; }
//        public string SourceIpv4Address { get; set; }
//        public string DestIpv4Address { get; set; }
//        public bool IsBlacklisted { get; set; }
//        public DateTime Timestamp { get; set; }
//    }

//    class Program
//    {
//        static FileSystemWatcher watcher;
//        static TraceEventSession traceEventSession;
//        static HashSet<string> monitoredProcesses;
//        static HashSet<string> blacklistIPs;
//        static Dictionary<int, string> ncProcesses = new Dictionary<int, string>();
//        static Dictionary<int, string> processNames = new Dictionary<int, string>();
//        private static List<int> toRemove = new List<int>();

//        //private static ElasticClient client;

//        static void Main(string[] args)
//        {
//            var uri = new Uri("http://localhost:9200");

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

//            if (!(TraceEventSession.IsElevated() ?? false))
//            {
//                Console.WriteLine("Please run me as administrator");
//                return;
//            }

//            // 读取 XML 配置文件
//            var config = XDocument.Load("C:\\Users\\frank\\OneDrive\\桌面\\etw\\etwrole.xml");
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
//        }

//        static void InitializeETW()
//        {
//            traceEventSession = new TraceEventSession("MyETWSession");
//            traceEventSession.EnableKernelProvider(
//                    KernelTraceEventParser.Keywords.NetworkTCPIP |
//                    KernelTraceEventParser.Keywords.Process |
//                    KernelTraceEventParser.Keywords.ImageLoad);
//            traceEventSession.EnableProvider("Microsoft-Windows-TCPIP");

//            // ProcessStart
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
//                //indexdatatoelasticsearch(processevent, "etw-events");
//                if (data.ProcessName.ToLower().Contains("nc"))
//                {
//                    Console.WriteLine($"NC process started: {data.ProcessName} (PID: {data.ProcessID})");

//                    string filePath = GetProcessFilePath(data.ProcessID);
//                    if (!string.IsNullOrEmpty(filePath))
//                    {
//                        Console.WriteLine($"File Path: {filePath}");
//                        ComputeHashes(filePath);
//                    }
//                }
//            };

//            traceEventSession.Source.Kernel.ProcessStop += data =>
//            {
//                var processEvent = new ProcessEvent
//                {
//                    ProcessName = data.ProcessName,
//                    ProcessId = data.ProcessID,
//                    CommandLine = data.CommandLine,
//                    Timestamp = DateTime.UtcNow,
//                    EventType = "ProcessStop"
//                };
//                OnProcessStopped(data);
//                //IndexDataToElasticsearch(processEvent, "etw-events");
//            };

//            //TCPIP
//            traceEventSession.Source.Dynamic.All += data =>
//            {
//                if (data.ProviderName == "Microsoft-Windows-TCPIP" && data.EventName == "TcpipSendSlowPath")
//                {
//                    var tcpIpEvent = new TcpIpEvent
//                    {
//                        EventName = data.EventName,
//                        Timestamp = DateTime.UtcNow
//                    };

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
//                    tcpIpEvent.IsBlacklisted = blacklistIPs.Contains(tcpIpEvent.SourceIpv4Address) || blacklistIPs.Contains(tcpIpEvent.DestIpv4Address);
//                    //IndexDataToElasticsearch(tcpIpEvent, "tcpip-events");
//                }
//            };


//            //traceEventSession.Source.Kernel.ProcessStart += data =>
//            //{
//            //    if (data.ProcessName.ToLower().Contains("nc"))
//            //    {
//            //        Console.WriteLine($"Debug: Process {data.ProcessName} started with Command Line: {data.CommandLine}");
//            //        string[] commandParts = data.CommandLine.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
//            //        if (commandParts.Length > 1 && Regex.IsMatch(commandParts[1], @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"))
//            //        {
//            //            string ipAddress = commandParts[1];
//            //            ncProcesses[data.ProcessID] = ipAddress;
//            //            Console.WriteLine($"[ProcessStart] NC process started with PID: {data.ProcessID}, IP: {ipAddress}");
//            //        }
//            //        else
//            //        {
//            //            Console.WriteLine("IP address not found or invalid in the command line.");
//            //        }
//            //    }
//            //};


//            //// 監聽 TCP/IP 連接
//            traceEventSession.Source.Dynamic.All += data =>
//            {
//                if (data.ProviderName == "Microsoft-Windows-TCPIP" && (data.EventName == "TcpipSendSlowPath" || data.EventName == "TcpipReceive"))
//                {
//                    string destIp = ConvertToIPAddressString((int)data.PayloadByName("DestIPv4Address"));

//                    foreach (var kvp in ncProcesses)
//                    {
//                        if (kvp.Value == destIp && blacklistIPs.Contains(destIp))
//                        {
//                            Console.WriteLine($"Detected NC process (PID: {kvp.Key}) attempting to connect to blacklisted IP: {destIp}");
//                            TerminateProcess(kvp.Key);
//                            toRemove.Add(kvp.Key);  // 將要移除的進程 ID 添加到列表
//                        }
//                    }

//                    // 移除已終止的進程
//                    foreach (int pid in toRemove)
//                    {
//                        ncProcesses.Remove(pid);
//                    }
//                    toRemove.Clear(); // 清理臨時列表以供下次使用
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
//                if (!process.HasExited)
//                {
//                    process.Kill();
//                    Console.WriteLine($"Terminated nc process {processId} due to connection attempt to specified IP.");
//                    // 這裡不再需要手動移除，因為我們在事件處理器中處理了
//                }
//            }
//            catch (Exception ex)
//            {
//                Console.WriteLine($"Failed to terminate process {processId}: {ex.Message}");
//            }
//        }


//        private static string ConvertToIPAddressString(int ipAddress)
//        {
//            return new IPAddress(BitConverter.GetBytes(ipAddress)).ToString();
//        }
//        //private static string ConvertToIPAddressString(int ipAddress)
//        //{
//        //    return new IPAddress(BitConverter.GetBytes(ipAddress)).ToString();
//        //}
//        //private static void TerminateProcess(int processId)
//        //{
//        //    try
//        //    {
//        //        Process process = Process.GetProcessById(processId);
//        //        if (!process.HasExited) // 检查进程是否仍在运行
//        //        {
//        //            process.Kill(); // 终止进程
//        //            Console.WriteLine($"Process {processId} terminated.");
//        //            LogProcessStop(processId, process.ProcessName);
//        //        }
//        //        else
//        //        {
//        //            Console.WriteLine($"Process {processId} has already exited.");
//        //        }
//        //    }
//        //    catch (ArgumentException ex)
//        //    {
//        //        Console.WriteLine($"Error: The process {processId} does not exist. {ex.Message}");
//        //    }
//        //    catch (InvalidOperationException ex)
//        //    {
//        //        Console.WriteLine($"Error: The process {processId} has already exited. {ex.Message}");
//        //    }
//        //    catch (Exception ex)
//        //    {
//        //        Console.WriteLine($"Error terminating process {processId}: {ex.Message}");
//        //    }
//        //}

//        //private static void LogProcessStop(int processId, string processName)
//        //{
//        //    Console.WriteLine($"[ProcessStop] Process {processName} (PID: {processId}) has been terminated.");
//        //}

//        //static void InitializeTCPIP()
//        //{
//        //    string sessionName = "TcpIpMonitoringSession";
//        //    var tcpIpSession = new TraceEventSession(sessionName);

//        //    tcpIpSession.EnableProvider("Microsoft-Windows-TCPIP");

//        //    tcpIpSession.Source.Dynamic.All += data =>
//        //    {
//        //        if (data.ProviderName == "Microsoft-Windows-TCPIP" && data.EventName == "TcpipSendSlowPath")
//        //        {
//        //            Console.WriteLine($"Event Name: {data.EventName}");
//        //            foreach (var payloadName in data.PayloadNames)
//        //            {
//        //                var payloadValue = data.PayloadByName(payloadName);
//        //                if (payloadValue != null)
//        //                {
//        //                    if (payloadName == "SourceIPv4Address" || payloadName == "DestIPv4Address")
//        //                    {
//        //                        var ipAddressString = ConvertToIPAddressString((int)payloadValue);
//        //                        Console.WriteLine($" {payloadName}: {ipAddressString}");

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
//        //    tcpIpSession.Source.Process();
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

//        //private static void IndexDataToElasticsearch<T>(T data, string indexName) where T : class
//        //{
//        //    if (!(client.Indices.Exists(indexName).Exists))
//        //    {
//        //        var createIndexResponse = client.Indices.Create(indexName, c => c.Map<T>(m => m.AutoMap())
//        //            .Settings(s => s
//        //                .NumberOfShards(1)
//        //                .NumberOfReplicas(1)));
//        //    }

//        //    var response = client.Index(data, idx => idx.Index(indexName));
//        //    if (!response.IsValid)
//        //    {
//        //        Console.WriteLine($"Error indexing data to Elasticsearch: {response.OriginalException.Message}");
//        //    }
//        //}
//    }
//}
