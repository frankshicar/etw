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
    using Nest;
    using Elasticsearch.Net;
    using System;
    using System.Threading.Tasks;


        class Program
        {
            public static ElasticClient client;
            static async Task Main(string[] args)
            {
                try
                {
                    Console.WriteLine("Starting System Monitoring...");

                    // 配置文件路徑
                    string configPath = "C:/Users/brad9/Desktop/ETW-logplatform project/ETW_Competition_4/ConsoleApp1/etwrole.xml"; // 請確保這個路徑正確
                    if (args.Length > 0)
                    {
                        configPath = args[0];
                    }

                    var uri = new Uri("http://localhost:9200");
                    var settings = new ConnectionSettings(uri)
                        .BasicAuthentication("elastic", "2xX02HZSSkjCVsY=MRw5");
                    client = new ElasticClient(settings);

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

    public class ProcessData
    {
        public string ProcessName { get; set; }
        public int ProcessID { get; set; }
        public DateTime CreateTime { get; set; }
        public string CommandLine { get; set; }
        public string ProcessType { get; set; }
        public string MD5 { get; set; }
        public string SHA1 { get; set; }
        public string SHA256 { get; set; }

    }

    public class TCPIPData
    {
        public string TCPIPEvent { get; set; }
        public string SourceIP { get; set;}
        public string DestIP { get; set;}
        public int ProcessID { get; set;}
        public DateTime CreateTime { get; set; }
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

        static void ComputeHashes(string filePath,string name,int ID,string command)
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
                    string md5HashString = BitConverter.ToString(md5Hash).Replace("-", "");
                    Console.WriteLine($"MD5: {md5HashString}");

                    // 計算 SHA1
                    stream.Position = 0;
                    byte[] sha1Hash = sha1.ComputeHash(stream);
                    string sha1HashString = BitConverter.ToString(sha1Hash).Replace("-", "");
                    Console.WriteLine($"SHA1: {sha1HashString}");

                    // 計算 SHA256
                    stream.Position = 0;
                    byte[] sha256Hash = sha256.ComputeHash(stream);
                    string sha256HashString = BitConverter.ToString(sha256Hash).Replace("-", "");
                    Console.WriteLine($"SHA256: {sha256HashString}");

                    var processdata = new ProcessData
                    {
                        ProcessName = name,
                        ProcessID = ID,
                        CommandLine = command,
                        CreateTime = DateTime.Now,
                        ProcessType = "ProcessStart",
                        MD5 = md5HashString,
                        SHA1 = sha1HashString,
                        SHA256 = sha256HashString,
                        
                    };

                    IndexDataToElasticsearch(processdata, "process");
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

                    var name = data.ProcessName;
                    var ID = data.ProcessID;
                    var command = data.CommandLine;

                    if (!string.IsNullOrEmpty(filePath) && File.Exists(filePath))
                    {
                        Console.WriteLine($"[ProcessFile] {filePath}");
                        // 使用Task來非同步計算雜湊值
                        Task.Run(() => ComputeHashes(filePath,name,ID,command))
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

            var processdata = new ProcessData()
            {
                ProcessName = data.ProcessName,
                ProcessID = data.ProcessID,
                CommandLine = data.CommandLine,
                CreateTime = DateTime.Now,
                ProcessType = "ProcessStop"
            };
            IndexDataToElasticsearch(processdata, "process");
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
        //tcpevent sourceip desetip processid time 
        private void OnTcpIpEvent(TraceEvent data)
        {
            try
            {
          
                if (data.ProviderName == "Microsoft-Windows-TCPIP" && data.EventName == "TcpipSendSlowPath")
                {
                    // 檢查各種 TCP/IP 相關事件
                    switch (data.EventName)
                    {
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

                    //var SourceIP = ConvertToIPAddress((int)data.PayloadByName("SourceIPv4Address"));
                    //var DestIP = ConvertToIPAddress((int)data.PayloadByName("DestIPv4Address"));
                    //if ((SourceIP != "0.0.0.0" || DestIP != "0.0.0.0"))
                    //{
                    //    var tcpipData = new TCPIPData()
                    //    {
                    //        TCPIPEvent = data.EventName,
                    //        SourceIP = SourceIP,
                    //        DestIP = DestIP,
                    //        ProcessID = data.ProcessID,
                    //        CreateTime = DateTime.Now,
                    //    };

                    //    IndexDataToElasticsearch(tcpipData, "tcpip");
                    //}
                    
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

        private static void IndexDataToElasticsearch<T>(T data, string indexname) where T : class
        {
            var client = Program.client;
            if (!(client.Indices.Exists(indexname).Exists))
            {
                var createIndexResponse = client.Indices.Create(indexname, c => c.Map<T>(m => m.AutoMap())
                .Settings(s => s
                .NumberOfShards(1)
                .NumberOfReplicas(1)));

            }

            var response = client.Index(data, idx => idx.Index(indexname));

        }

        // 輔助方法...
    }
}


