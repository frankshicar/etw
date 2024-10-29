
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

    namespace SystemMonitoring
    {
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

            // Start file hash monitoring
            _ = StartFileHashMonitoring(_cancellationTokenSource.Token);

            // Start ETW processing
            await Task.Run(() => _traceSession.Source.Process());
        }

        private async Task StartFileHashMonitoring(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                foreach (var file in Directory.GetFiles(_config.WatchPath, "*.*", SearchOption.AllDirectories))
                {
                    await CheckFileHash(file);
                }
                await Task.Delay(TimeSpan.FromMinutes(5), cancellationToken);
            }
        }


        private async Task<FileHashInfo> CalculateFileHashes(string filePath)
        {
            var hashInfo = new FileHashInfo
            {
                FilePath = filePath,
                LastChecked = DateTime.UtcNow
            };

            // 使用緩衝區讀取，避免一次性將整個文件載入內存
            const int bufferSize = 8192; // 8KB 緩衝區
            var buffer = new byte[bufferSize];

            using (var md5 = MD5.Create())
            using (var sha1 = SHA1.Create())
            using (var sha256 = SHA256.Create())
            {
                try
                {
                    // 使用 FileShare.Read 允許其他程序讀取文件
                    using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize))
                    {
                        int bytesRead;
                        while ((bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                        {
                            md5.TransformBlock(buffer, 0, bytesRead, null, 0);
                            sha1.TransformBlock(buffer, 0, bytesRead, null, 0);
                            sha256.TransformBlock(buffer, 0, bytesRead, null, 0);
                        }

                        // 完成最後的哈希計算
                        md5.TransformFinalBlock(buffer, 0, 0);
                        sha1.TransformFinalBlock(buffer, 0, 0);
                        sha256.TransformFinalBlock(buffer, 0, 0);

                        // 獲取哈希值並轉換為字符串
                        hashInfo.MD5Hash = BitConverter.ToString(md5.Hash).Replace("-", "");
                        hashInfo.SHA1Hash = BitConverter.ToString(sha1.Hash).Replace("-", "");
                        hashInfo.SHA256Hash = BitConverter.ToString(sha256.Hash).Replace("-", "");
                    }

                    return hashInfo;
                }
                catch (IOException ex)
                {
                    throw new IOException($"無法讀取文件 {filePath}: {ex.Message}", ex);
                }
                catch (UnauthorizedAccessException ex)
                {
                    throw new UnauthorizedAccessException($"沒有權限訪問文件 {filePath}: {ex.Message}", ex);
                }
                catch (Exception ex)
                {
                    throw new Exception($"計算文件 {filePath} 的哈希值時發生錯誤: {ex.Message}", ex);
                }
            }
        }

        // 使用此方法的檢查函數
        private async Task CheckFileHash(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                {
                    Console.WriteLine($"[FileNotFound] {filePath} 不存在");
                    return;
                }

                var hashInfo = await CalculateFileHashes(filePath);

                if (_fileHashes.TryGetValue(filePath, out var existingHash))
                {
                    if (existingHash.SHA256Hash != hashInfo.SHA256Hash)
                    {
                        Console.WriteLine($"[HashChange] 文件: {filePath}");
                        Console.WriteLine($"舊的 Hash (SHA256): {existingHash.SHA256Hash}");
                        Console.WriteLine($"新的 Hash (SHA256): {hashInfo.SHA256Hash}");

                        // 可以添加更詳細的比較
                        if (existingHash.MD5Hash != hashInfo.MD5Hash)
                            Console.WriteLine($"MD5 已改變");
                        if (existingHash.SHA1Hash != hashInfo.SHA1Hash)
                            Console.WriteLine($"SHA1 已改變");
                    }
                }

                _fileHashes[filePath] = hashInfo;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[HashError] 計算文件 {filePath} 的哈希值失敗: {ex.Message}");
            }
        }

        private void OnProcessStarted(ProcessTraceData data)
        {
            _processNames[data.ProcessID] = data.ProcessName;
            Console.WriteLine($"[ProcessStart] {data.ProcessName} (PID: {data.ProcessID})");
            Console.WriteLine($"Command Line: {data.CommandLine}");

            if (_config.MonitoredProcesses.Contains(data.ProcessName))
            {
                var filePath = GetProcessFilePath(data.ProcessID);
                if (!string.IsNullOrEmpty(filePath))
                {
                    _ = CheckFileHash(filePath);
                }
            }
        }

        private void OnProcessStopped(ProcessTraceData data)
        {
            Console.WriteLine($"[ProcessStop] {data.ProcessName} (PID: {data.ProcessID})");
            _processNames.Remove(data.ProcessID);
        }

        private void OnTcpIpEvent(TraceEvent data)
        {
            if (data.ProviderName == "Microsoft-Windows-TCPIP" && data.EventName == "TcpipSendSlowPath")
            {
                var sourceIp = ConvertToIPAddress((int)data.PayloadByName("SourceIPv4Address"));
                var destIp = ConvertToIPAddress((int)data.PayloadByName("DestIPv4Address"));

                if (_config.BlacklistedIPs.Contains(sourceIp) || _config.BlacklistedIPs.Contains(destIp))
                {
                    Console.WriteLine($"[BlacklistedIP] Process {data.ProcessID} attempting to connect to {destIp}");
                    TerminateProcess(data.ProcessID);
                }
            }
        }

        private void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            Console.WriteLine($"[FileChanged] {e.FullPath}");
            _ = CheckFileHash(e.FullPath);
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
                return process.MainModule.FileName;
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
