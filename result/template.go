package result

// htmlTemplate HTML报告模板
const htmlTemplate = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FinderFuzz 扫描报告</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            text-align: center;
        }

        .stat-card h3 {
            color: #667eea;
            font-size: 2em;
            margin-bottom: 5px;
        }

        .stat-card p {
            color: #666;
            font-size: 0.9em;
        }

        .section {
            background: white;
            margin-bottom: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }

        .section-header {
            background: #f8f9fa;
            padding: 20px;
            border-bottom: 1px solid #e9ecef;
        }

        .section-header h2 {
            color: #495057;
            margin-bottom: 5px;
        }

        .section-header .description {
            color: #6c757d;
            font-size: 0.9em;
        }

        .section-content {
            padding: 20px;
        }

        .table-container {
            overflow-x: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }

        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e9ecef;
        }

        th {
            background-color: #f8f9fa;
            font-weight: 600;
            color: #495057;
        }

        tr:hover {
            background-color: #f8f9fa;
        }

        .status {
            padding: 5px 5px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
        }

        .status.success {
            background-color: #d4edda;
            color: #155724;
        }

        .status.redirect {
            background-color: #fff3cd;
            color: #856404;
        }

        .status.client-error {
            background-color: #f8d7da;
            color: #721c24;
        }

        .status.server-error {
            background-color: #f5c6cb;
            color: #721c24;
        }

        .status.unknown {
            background-color: #e2e3e5;
            color: #383d41;
        }

        .url {
            word-break: break-all;
            max-width: 300px;
        }

        .source-link {
            color: #667eea;
            text-decoration: none;
            cursor: pointer;
        }

        .source-link:hover {
            text-decoration: underline;
            color: #5a6fd8;
        }

        .clickable-icon {
            cursor: pointer;
            margin-left: 8px;
            color: #667eea;
            font-size: 1.2em;
        }

        .clickable-icon:hover {
            color: #5a6fd8;
            transform: scale(1.1);
        }

        .section-title {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .method {
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.8em;
            font-weight: bold;
        }

        .method.get {
            background-color: #d1ecf1;
            color: #0c5460;
        }

        .method.post {
            background-color: #d4edda;
            color: #155724;
        }

        .method.put {
            background-color: #fff3cd;
            color: #856404;
        }

        .method.delete {
            background-color: #f8d7da;
            color: #721c24;
        }

        .sensitive-type {
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.8em;
            font-weight: bold;
            background-color: #f8d7da;
            color: #721c24;
        }

        .fuzz-type {
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.8em;
            background-color: #e2e3e5;
            color: #383d41;
        }

        .filter-info {
            background-color: #d1ecf1;
            color: #0c5460;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 15px;
            font-size: 0.9em;
        }

        .no-data {
            text-align: center;
            color: #6c757d;
            font-style: italic;
            padding: 40px;
        }

        .collapsible {
            cursor: pointer;
            user-select: none;
        }

        .collapsible:hover {
            background-color: #e9ecef;
        }

        .collapsible::before {
            content: '▼';
            margin-right: 8px;
            transition: transform 0.3s;
        }

        .collapsible.collapsed::before {
            transform: rotate(-90deg);
        }

        .collapsible-content {
            display: block;
        }

        .collapsible-content.hidden {
            display: none;
        }

        .api-list {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            margin-top: 5px;
        }

        .api-item {
            background-color: white;
            padding: 5px 8px;
            margin: 2px 0;
            border-radius: 3px;
            font-family: monospace;
            font-size: 0.9em;
        }

        .vulnerable {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            background-color: #f8d7da;
            color: #721c24;
        }

        .safe {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            background-color: #d4edda;
            color: #155724;
        }

        .authority-reason {
            font-size: 0.9em;
            color: #6c757d;
            font-style: italic;
        }

        .vulnerable-url {
            background-color: #fff5f5 !important;
            border-left: 4px solid #f56565;
        }

        .requires-auth {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            background-color: #fff3cd;
            color: #856404;
        }

        .no-auth-required {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            background-color: #d4edda;
            color: #155724;
        }

        .vulnerable-url:hover {
            background-color: #fed7d7 !important;
        }

        .action-buttons {
            display: flex;
            gap: 5px;
            justify-content: center;
        }
        
        .btn-small {
            background: #007bff;
            color: white;
            border: none;
            padding: 4px 8px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            transition: background-color 0.3s;
        }
        
        .btn-small:hover {
            background: #0056b3;
        }
        
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
        }
        
        .modal-content {
            background-color: #fefefe;
            margin: 5% auto;
            padding: 20px;
            border: 1px solid #888;
            width: 80%;
            max-width: 800px;
            border-radius: 8px;
            max-height: 80vh;
            overflow-y: auto;
        }
        
        .close {
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }
        
        .request-btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 4px 8px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            margin: 2px;
            transition: background-color 0.3s;
        }
        
        .request-btn:hover {
            background: #5a6fd8;
        }
        
        .request-response-content {
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 15px;
            margin: 10px 0;
            font-family: monospace;
            font-size: 14px;
            white-space: pre-wrap;
            word-wrap: break-word;
            max-height: 300px;
            overflow-y: auto;
        }
        
        .close:hover {
            color: black;
        }
        
        .request-data {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 15px;
            margin: 10px 0;
            font-family: 'Courier New', monospace;
            white-space: pre-wrap;
            word-wrap: break-word;
            max-height: 300px;
            overflow-y: auto;
        }

        .footer {
            text-align: center;
            color: #6c757d;
            margin-top: 40px;
            padding: 20px;
            border-top: 1px solid #e9ecef;
        }

        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }

            .header {
                padding: 20px;
            }

            .header h1 {
                font-size: 2em;
            }

            .stats {
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            }

            table {
                font-size: 0.9em;
            }

            th, td {
                padding: 8px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 头部 -->
        <div class="header">
            <h1>🔍 FinderFuzz 扫描报告</h1>
            <div class="subtitle">生成时间: {{formatTime .Timestamp}}</div>
            {{if hasFilter}}
            <div class="subtitle">状态码过滤: {{filterString}}</div>
            {{end}}
        </div>

        <!-- 统计信息 -->
        <div class="stats">
            <div class="stat-card">
                <h3>{{.Stats.TotalFuzzResults}}</h3>
                <p>模糊测试结果</p>
            </div>
            <div class="stat-card">
                <h3>{{.Stats.SuccessCount}}</h3>
                <p>成功响应 (2xx)</p>
            </div>
            <div class="stat-card">
                <h3>{{.Stats.JSFilesCount}}</h3>
                <p>JS文件</p>
            </div>
            <div class="stat-card">
                <h3>{{.Stats.SensitiveInfoCount}}</h3>
                <p>敏感信息</p>
            </div>
            <div class="stat-card">
                <h3>{{.Stats.LinksCount}}</h3>
                <p>发现链接</p>
            </div>
            {{if .ParamFuzzResults}}
            <div class="stat-card">
                <h3>{{.Stats.ParamFuzzResultsCount}}</h3>
                <p>参数模糊测试</p>
            </div>
            {{end}}
            {{if .AuthorityResults}}
            <div class="stat-card">
                <h3 style="color: #dc3545;">{{len .VulnerableResults}}</h3>
                <p>需要权限的接口</p>
            </div>
            <div class="stat-card">
                <h3>{{len .AuthorityResults}}</h3>
                <p>权限检测</p>
            </div>
            {{end}}
            {{if .PrivilegeEscalationResults}}
            <div class="stat-card">
                <h3 style="color: #dc3545;">{{len (filterVulnerablePrivilege .PrivilegeEscalationResults)}}</h3>
                <p>未授权访问漏洞</p>
            </div>
            <div class="stat-card">
                <h3>{{len .PrivilegeEscalationResults}}</h3>
                <p>未授权访问检测</p>
            </div>
            {{end}}
        </div>

        <!-- URL to Host -->
        <div class="section">
            <div class="section-header">
                <div class="section-title">
                    <h2>🔗 URL to Host</h2>
                    <span class="clickable-icon" onclick="window.open('#related-urls', '_blank')" title="在新窗口打开">🔗</span>
                </div>
                <div class="description">与目标域名相关的链接</div>
            </div>
            <div class="section-content">
                {{if .RelatedLinks}}
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>URL</th>
                                <th>状态码</th>
                                <th>大小</th>
                                <th>标题</th>
                                <th>来源</th>
                                <th>页面内容</th>
                            </tr>
                        </thead>
                        <tbody>
                            {{range .RelatedLinks}}
                            <tr>
                                <td class="url"><a href="{{.Url}}" target="_blank" class="source-link">{{truncate .Url 80}}</a></td>
                                <td><span class="status {{statusClass .Status}}">{{.Status}}</span></td>
                                <td>{{formatSize .Size}}</td>
                                <td>{{truncate .Title 50}}</td>
                                <td>
                                    {{if .Source}}
                                        <a href="{{.Source}}" target="_blank" class="source-link">{{truncate .Source 50}}</a>
                                    {{else}}
                                        -
                                    {{end}}
                                </td>
                                <td>
                                    {{if .Content}}
                                        <span class="content-summary">{{.Content}}</span>
                                    {{else if eq .Status "401"}}
                                        <span class="status client-error">需要鉴权</span>
                                    {{else if eq .Status "403"}}
                                        <span class="status client-error">禁止访问</span>
                                    {{else if and (eq .Status "200") (or (contains .Title "权限") (contains .Title "鉴权") (contains .Title "未授权") (contains .Title "需要鉴权"))}}
                                        <span class="status client-error">需要鉴权</span>
                                    {{else if eq .Status "200"}}
                                        <span class="status success">正常访问</span>
                                    {{else}}
                                        <span class="status {{statusClass .Status}}">{{.Status}}</span>
                                    {{end}}
                                </td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
                {{else}}
                <div class="no-data">未发现相关链接</div>
                {{end}}
            </div>
        </div>

        <!-- URL to Other -->
        <div class="section">
            <div class="section-header collapsible collapsed" onclick="toggleSection('unrelated-urls')">
                <div class="section-title">
                    <h2>🔗 URL to Other</h2>
                    <span class="clickable-icon" onclick="event.stopPropagation(); window.open('#unrelated-urls', '_blank')" title="在新窗口打开">🔗</span>
                </div>
                <div class="description">与目标域名无关的外部链接</div>
            </div>
            <div class="section-content collapsible-content hidden" id="unrelated-urls">
                {{if .UnrelatedLinks}}
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>URL</th>
                                <th>状态码</th>
                                <th>大小</th>
                                <th>标题</th>
                                <th>来源</th>
                            </tr>
                        </thead>
                        <tbody>
                            {{range .UnrelatedLinks}}
                            <tr>
                                <td class="url"><a href="{{.Url}}" target="_blank" class="source-link">{{truncate .Url 80}}</a></td>
                                <td><span class="status {{statusClass .Status}}">{{.Status}}</span></td>
                                <td>{{formatSize .Size}}</td>
                                <td>{{truncate .Title 50}}</td>
                                <td>
                                    {{if .Source}}
                                        <a href="{{.Source}}" target="_blank" class="source-link">{{truncate .Source 50}}</a>
                                    {{else}}
                                        -
                                    {{end}}
                                </td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
                {{else}}
                <div class="no-data">未发现无关链接</div>
                {{end}}
            </div>
        </div>

        <!-- 模糊测试结果 -->
        <div class="section">
            <div class="section-header">
                <div class="section-title">
                    <h2>🎯 模糊测试结果</h2>
                    <span class="clickable-icon" onclick="window.open('#fuzz-results', '_blank')" title="在新窗口打开">🚀</span>
                </div>
                <div class="description">路径的FUZZ</div>
            </div>
            <div class="section-content">
                {{if .FuzzResults}}
                {{if hasFilter}}
                <div class="filter-info">
                    📊 已应用状态码过滤器: {{filterString}}
                </div>
                {{end}}
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>URL</th>
                                <th>方法</th>
                                <th>状态码</th>
                                <th>大小</th>
                                <th>标题</th>
                                <th>来源</th>
                                <th>模糊类型</th>
                                <th>载荷</th>
                            </tr>
                        </thead>
                        <tbody>
                            {{range .FuzzResults}}
                            <tr>
                                <td class="url"><a href="{{.URL}}" target="_blank" class="source-link">{{.URL}}</a></td>
                                <td><span class="method {{.Method | lower}}">{{.Method}}</span></td>
                                <td><span class="status {{statusClass .Status}}">{{.Status}}</span></td>
                                <td>{{formatSize .Size}}</td>
                                <td>{{truncate .Title 50}}</td>
                                <td><a href="{{.Source}}" target="_blank" class="source-link">{{truncate .Source 30}}</a></td>
                                <td><span class="fuzz-type">{{.FuzzType}}</span></td>
                                <td>{{truncate .Payload 20}}</td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
                {{else}}
                <div class="no-data">暂无模糊测试结果</div>
                {{end}}
            </div>
        </div>

        <!-- 参数模糊测试结果 -->
        <div class="section">
            <div class="section-header">
                <div class="section-title">
                    <h2>🎯 参数模糊测试结果</h2>
                    <span class="clickable-icon" onclick="window.open('#param-fuzz-results', '_blank')" title="在新窗口打开">🎯</span>
                </div>
                <div class="description">参数错误提示检测和动态参数模糊测试</div>
            </div>
            <div class="section-content">
                {{if .ParamFuzzResults}}
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>URL</th>
                                <th>方法</th>
                                <th>原始状态码</th>
                                <th>成功参数</th>
                                <th>错误提示</th>
                                <th>参数来源</th>
                                <th>测试结果数</th>
                                <th>操作</th>
                            </tr>
                        </thead>
                        <tbody>
                            {{range $paramIndex, $paramResult := .ParamFuzzResults}}
                            <tr>
                                <td class="url"><a href="{{$paramResult.URL}}" target="_blank" class="source-link">{{truncate $paramResult.URL 60}}</a></td>
                                <td><span class="method {{$paramResult.Method | lower}}">{{$paramResult.Method}}</span></td>
                                <td><span class="status {{statusClass $paramResult.OriginalStatus}}">{{$paramResult.OriginalStatus}}</span></td>
                                <td>
                                    {{if $paramResult.SuccessfulParams}}
                                        {{range $index, $param := $paramResult.SuccessfulParams}}
                                            {{if $index}}, {{end}}<span class="sensitive-type">{{$param}}</span>
                                        {{end}}
                                    {{else}}
                                        -
                                    {{end}}
                                </td>
                                <td>
                                    {{if $paramResult.ErrorHints}}
                                        {{range $index, $hint := $paramResult.ErrorHints}}
                                            {{if $index}}<br>{{end}}{{truncate $hint 30}}
                                        {{end}}
                                    {{else}}
                                        -
                                    {{end}}
                                </td>
                                <td><span class="fuzz-type">{{$paramResult.ParamSource}}</span></td>
                                <td>{{len $paramResult.TestResults}}</td>
                                <td>
                                    {{if $paramResult.TestResults}}
                                        <div class="action-buttons">
                                            <button class="btn-small" onclick="showParamRequestData({{$paramIndex}})" title="查看请求数据包">📋</button>
                                        </div>
                                    {{else}}
                                        -
                                    {{end}}
                                </td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
                {{else}}
                <div class="no-data">暂无参数模糊测试结果</div>
                {{end}}
            </div>
        </div>

        <!-- 域名信息 -->
        <div class="section">
            <div class="section-header">
                <h2>🌐 域名信息</h2>
                <div class="description">发现的域名和IP地址信息</div>
            </div>
            <div class="section-content">
                {{if .DomainInfo}}
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>域名/IP</th>
                                <th>类型</th>
                                <th>云服务</th>
                                <th>来源</th>
                            </tr>
                        </thead>
                        <tbody>
                            {{range .DomainInfo}}
                            <tr>
                                <td>
                                    {{if .IP}}
                                        <strong>{{.Domain}}</strong><br>
                                        <small>{{.IP}}</small>
                                    {{else}}
                                        {{.Domain}}
                                    {{end}}
                                </td>
                                <td><span class="fuzz-type">{{.Type}}</span></td>
                                <td>
                                    {{if .CloudType}}
                                        <span class="fuzz-type">{{.CloudType}}</span>
                                    {{else}}
                                        -
                                    {{end}}
                                </td>
                                <td><a href="{{.Source}}" target="_blank" class="source-link">{{truncate .Source 50}}</a></td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
                {{else}}
                <div class="no-data">未发现域名信息</div>
                {{end}}
            </div>
        </div>

        <!-- 敏感信息 -->
        <div class="section">
            <div class="section-header">
                <h2>🔐 敏感信息</h2>
                <div class="description">发现的敏感数据，包括密钥、密码、JWT等</div>
            </div>
            <div class="section-content">
                {{if .SensitiveInfo}}
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>类型</th>
                                <th>值</th>
                                <th>来源</th>
                            </tr>
                        </thead>
                        <tbody>
                            {{range .SensitiveInfo}}
                            <tr>
                                <td><span class="sensitive-type">{{.Type}}</span></td>
                                <td>{{truncate .Value 80}}</td>
                                <td class="url"><a href="{{.Source}}" target="_blank" class="source-link">{{.Source}}</a></td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
                {{else}}
                <div class="no-data">未发现敏感信息</div>
                {{end}}
            </div>
        </div>

        <!-- 权限检测结果 -->
        <div class="section">
            <div class="section-header">
                <div class="section-title">
                    <h2>🛡️ 需要权限的接口</h2>
                    <span class="clickable-icon" onclick="window.open('#authority-results', '_blank')" title="在新窗口打开">🛡️</span>
                </div>
                <div class="description">发现的需要权限才能访问的URL</div>
            </div>
            <div class="section-content">
                {{if .VulnerableResults}}
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>URL</th>
                                <th>认证状态码</th>
                                <th>无认证状态码</th>
                                <th>检测结果</th>
                                <th>操作</th>
                            </tr>
                        </thead>
                        <tbody>
                            {{range $index, $result := .VulnerableResults}}
                            <tr class="vulnerable-url">
                                <td class="url"><a href="{{$result.URL}}" target="_blank" class="source-link">{{truncate $result.URL 80}}</a></td>
                                <td>
                                    {{if $result.HasAuth}}
                                        <span class="status {{statusClass $result.AuthStatusCode}}">{{$result.AuthStatusCode}}</span>
                                    {{else}}
                                        <span style="color: #6c757d;">-</span>
                                    {{end}}
                                </td>
                                <td>
                                    {{if $result.NoAuth}}
                                        <span class="status {{statusClass $result.NoAuthStatusCode}}">{{$result.NoAuthStatusCode}}</span>
                                    {{else}}
                                        <span style="color: #6c757d;">-</span>
                                    {{end}}
                                </td>
                                <td>
                                    {{if $result.Reason}}
                                        <span class="authority-reason">{{$result.Reason}}</span>
                                    {{else}}
                                        <span style="color: #6c757d;">需要权限访问</span>
                                    {{end}}
                                </td>
                                <td>
                                    <div class="action-buttons">
                                        <button class="btn-small" onclick="showRequestData({{$index}})" title="查看请求数据包">📋</button>
                                        <button class="btn-small" onclick="accessWithAuth('{{$result.URL}}')" title="带认证访问">🔐</button>
                                    </div>
                                </td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
                {{else}}
                <div class="no-data">未发现需要权限的接口</div>
                {{end}}
            </div>
        </div>

        <!-- 未授权访问检测结果 -->
        <div class="section">
            <div class="section-header">
                <div class="section-title">
                    <h2>🔓 未授权访问检测结果</h2>
                    <span class="clickable-icon" onclick="window.open('#unauthority-results', '_blank')" title="在新窗口打开">🔓</span>
                </div>
                <div class="description">检测到的未授权访问漏洞</div>
            </div>
            <div class="section-content">
                {{$vulnerableUnauthorityResults := (filterVulnerableUnauthority .UnauthorityResults)}}
                {{if $vulnerableUnauthorityResults}}
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>URL</th>
                                <th>认证状态码</th>
                                <th>无认证状态码</th>
                                <th>漏洞状态</th>
                                <th>检测结果</th>
                                <th>操作</th>
                            </tr>
                        </thead>
                        <tbody>
                            {{range $index, $result := $vulnerableUnauthorityResults}}
                            <tr class="vulnerable-url">
                                <td class="url"><a href="{{$result.URL}}" target="_blank" class="source-link">{{truncate $result.URL 80}}</a></td>
                                <td><span class="status {{statusClass $result.AuthStatusCode}}">{{$result.AuthStatusCode}}</span></td>
                                <td><span class="status {{statusClass $result.NoAuthStatusCode}}">{{$result.NoAuthStatusCode}}</span></td>
                                <td>
                                    <span class="status client-error">🚨 漏洞</span>
                                </td>
                                <td>
                                    {{if $result.Reason}}
                                        <span class="authority-reason">{{$result.Reason}}</span>
                                    {{else}}
                                        <span style="color: #6c757d;">-</span>
                                    {{end}}
                                </td>
                                <td>
                                    <div class="action-buttons">
                                        <button class="btn-small" onclick="showUnauthorityRequestData({{$index}})" title="查看请求数据包">📋</button>
                                        <button class="btn-small" onclick="window.open('{{$result.URL}}', '_blank')" title="直接访问">🔗</button>
                                    </div>
                                </td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
                {{else}}
                <div class="no-data">未发现未授权访问漏洞</div>
                {{end}}
            </div>
        </div>



        <!-- JS to Host -->
        <div class="section">
            <div class="section-header collapsible" onclick="toggleSection('related-js')">
                <div class="section-title">
                    <h2>📄 JS to Host</h2>
                    <span class="clickable-icon" onclick="event.stopPropagation(); window.open('#related-js', '_blank')" title="在新窗口打开">📄</span>
                </div>
                <div class="description">与目标域名相关的JS文件</div>
            </div>
            <div class="section-content collapsible-content" id="related-js">
                {{if .RelatedJSFiles}}
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>URL</th>
                                <th>状态码</th>
                                <th>大小</th>
                                <th>来源</th>
                                <th>API接口</th>
                            </tr>
                        </thead>
                        <tbody>
                            {{range .RelatedJSFiles}}
                            <tr>
                                <td class="url"><a href="{{.Url}}" target="_blank" class="source-link">{{.Url}}</a></td>
                                <td><span class="status {{statusClass .Status}}">{{.Status}}</span></td>
                                <td>{{formatSize .Size}}</td>
                                <td><a href="{{.Source}}" target="_blank" class="source-link">{{truncate .Source 30}}</a></td>
                                <td>
                                    {{if .APIs}}
                                    <div class="api-list">
                                        {{range .APIs}}
                                        <div class="api-item">{{.}}</div>
                                        {{end}}
                                    </div>
                                    {{else}}
                                    <span style="color: #6c757d;">无</span>
                                    {{end}}
                                </td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
                {{else}}
                <div class="no-data">未发现相关JS文件</div>
                {{end}}
            </div>
        </div>

        <!-- JS to Other -->
        <div class="section">
            <div class="section-header collapsible collapsed" onclick="toggleSection('unrelated-js')">
                <div class="section-title">
                    <h2>📄 JS to Other</h2>
                    <span class="clickable-icon" onclick="event.stopPropagation(); window.open('#unrelated-js', '_blank')" title="在新窗口打开">📄</span>
                </div>
                <div class="description">与目标域名无关的外部JS文件</div>
            </div>
            <div class="section-content collapsible-content hidden" id="unrelated-js">
                {{if .UnrelatedJSFiles}}
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>URL</th>
                                <th>状态码</th>
                                <th>大小</th>
                                <th>来源</th>
                            </tr>
                        </thead>
                        <tbody>
                            {{range .UnrelatedJSFiles}}
                            <tr>
                                <td class="url"><a href="{{.Url}}" target="_blank" class="source-link">{{.Url}}</a></td>
                                <td><span class="status {{statusClass .Status}}">{{.Status}}</span></td>
                                <td>{{formatSize .Size}}</td>
                                <td><a href="{{.Source}}" target="_blank" class="source-link">{{truncate .Source 30}}</a></td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
                {{else}}
                <div class="no-data">未发现无关JS文件</div>
                {{end}}
            </div>
        </div>



        <!-- 页脚 -->
        <div class="footer">
            <p>由 FinderFuzz 工具生成 | 扫描时间: {{formatTime .Timestamp}}</p>
        </div>
    </div>

    <!-- 请求数据模态框 -->
    <div id="requestModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal()">&times;</span>
            <h3>请求数据包</h3>
            <div id="requestContent" class="request-data"></div>
        </div>
    </div>

    <script>
         // 嵌入权限检测结果数据
         const vulnerableResults = [
             {{range .VulnerableResults}}
             {
                 url: "{{.URL}}",
                 authRequest: {{printf "%q" .AuthRequest}},
                 authResponse: {{printf "%q" .AuthResponse}},
                 noAuthRequest: {{printf "%q" .NoAuthRequest}},
                 noAuthResponse: {{printf "%q" .NoAuthResponse}}
             },
             {{end}}
         ];
         
         // 嵌入未授权访问检测结果数据（仅包含有漏洞的）
         const vulnerableUnauthorityResults = [
             {{range .UnauthorityResults}}
             {{if .Vulnerable}}
             {
                 url: "{{.URL}}",
                 authRequest: {{printf "%q" .AuthRequest}},
                 authResponse: {{printf "%q" .AuthResponse}},
                 noAuthRequest: {{printf "%q" .NoAuthRequest}},
                 noAuthResponse: {{printf "%q" .NoAuthResponse}}
             },
             {{end}}
             {{end}}
         ];
         
         // 嵌入参数模糊测试结果数据（仅包含成功的测试结果）
         const paramFuzzResults = [
             {{range .ParamFuzzResults}}
             {
                 url: "{{.URL}}",
                 testResults: [
                     {{range .TestResults}}{{if .Success}}
                     {
                         paramName: "{{.ParamName}}",
                         paramValue: "{{.ParamValue}}",
                         success: {{.Success}},
                         requestData: {{printf "%q" .RequestData}},
                         responseData: {{printf "%q" .ResponseData}}
                     },
                     {{end}}{{end}}
                 ]
             },
             {{end}}
         ];
         

         
         function toggleSection(sectionId) {
             const content = document.getElementById(sectionId);
             const header = content.previousElementSibling;
             
             if (content.classList.contains('hidden')) {
                 content.classList.remove('hidden');
                 header.classList.remove('collapsed');
             } else {
                 content.classList.add('hidden');
                 header.classList.add('collapsed');
             }
         }

         // 添加表格行点击高亮效果
         document.addEventListener('DOMContentLoaded', function() {
             const rows = document.querySelectorAll('tbody tr');
             rows.forEach(row => {
                 row.addEventListener('click', function() {
                     // 移除其他行的高亮
                     rows.forEach(r => r.style.backgroundColor = '');
                     // 高亮当前行
                     this.style.backgroundColor = '#e3f2fd';
                 });
             });
         });

        // 显示请求数据包的函数（用于权限检测结果）
         function showRequestData(requestData, responseData, paramInfo) {
             const modal = document.getElementById('requestModal');
             const modalContent = document.getElementById('requestContent');
             
             if (typeof requestData === 'string' && typeof responseData === 'string') {
                 // 参数模糊测试的调用
                 const content = '=== 参数: ' + paramInfo + ' ===\n\n=== 请求包 (可直接复制使用) ===\n' + requestData + '\n\n=== 响应包 ===\n' + responseData;
                 modalContent.innerHTML = '<div class="request-response-content">' + content.replace(/\n/g, '<br>') + '</div>';
             } else {
                 // 权限检测结果的调用（原有逻辑）
                 const index = requestData; // 第一个参数是index
                 if (index < vulnerableResults.length) {
                       const result = vulnerableResults[index];
                       // 解析JSON字符串并格式化为可直接使用的HTTP数据包格式
                       const authReq = JSON.parse(result.authRequest).replace(/\\r\\n/g, '\n');
                       const authResp = JSON.parse(result.authResponse).replace(/\\r\\n/g, '\n');
                       const noAuthReq = JSON.parse(result.noAuthRequest).replace(/\\r\\n/g, '\n');
                       const noAuthResp = JSON.parse(result.noAuthResponse).replace(/\\r\\n/g, '\n');
                       
                       const requestDataContent = '=== 认证请求 (可直接复制使用) ===\n' + authReq + '\n\n=== 认证响应 ===\n' + authResp + '\n\n=== 无认证请求 (可直接复制使用) ===\n' + noAuthReq + '\n\n=== 无认证响应 ===\n' + noAuthResp;
                       modalContent.textContent = requestDataContent;
                   } else {
                       modalContent.textContent = '无法获取请求数据';
                   }
             }
             
             modal.style.display = 'block';
         }
         
         // 显示未授权访问检测请求数据包的函数
         function showUnauthorityRequestData(index) {
             const modal = document.getElementById('requestModal');
             const modalContent = document.getElementById('requestContent');
             
             if (index < vulnerableUnauthorityResults.length) {
                   const result = vulnerableUnauthorityResults[index];
                   // 解析JSON字符串并格式化为可直接使用的HTTP数据包格式
                   const authReq = JSON.parse(result.authRequest).replace(/\\r\\n/g, '\n');
                   const authResp = JSON.parse(result.authResponse).replace(/\\r\\n/g, '\n');
                   const noAuthReq = JSON.parse(result.noAuthRequest).replace(/\\r\\n/g, '\n');
                   const noAuthResp = JSON.parse(result.noAuthResponse).replace(/\\r\\n/g, '\n');
                   
                   const requestData = '=== 认证请求 (可直接复制使用) ===\n' + authReq + '\n\n=== 认证响应 ===\n' + authResp + '\n\n=== 无认证请求 (可直接复制使用) ===\n' + noAuthReq + '\n\n=== 无认证响应 ===\n' + noAuthResp;
                   modalContent.textContent = requestData;
               } else {
                   modalContent.textContent = '无法获取请求数据';
               }
             
             modal.style.display = 'block';
         }
         
         // 显示参数模糊测试请求数据包的函数
         function showParamRequestData(paramIndex) {
             const modal = document.getElementById('requestModal');
             const modalContent = document.getElementById('requestContent');
             
             if (paramIndex < paramFuzzResults.length) {
                 const paramResult = paramFuzzResults[paramIndex];
                 const testResults = paramResult.testResults;
                 
                 if (testResults && testResults.length > 0) {
                     let content = '=== 参数模糊测试结果 ===\n\n';
                     
                     testResults.forEach((testResult, index) => {
                         if (index > 0) content += '\n\n' + '='.repeat(50) + '\n\n';
                         
                         // 解析JSON字符串，保持原始的\r\n格式用于HTTP请求包
                         const requestData = JSON.parse(testResult.requestData);
                         const responseData = JSON.parse(testResult.responseData);
                         
                         content += '=== 参数: ' + testResult.paramName + '=' + testResult.paramValue + ' ===\n\n';
                         content += '=== 请求包 (可直接复制使用) ===\n' + requestData + '\n\n';
                         content += '=== 响应包 ===\n' + responseData;
                     });
                     
                     modalContent.textContent = content;
                 } else {
                     modalContent.textContent = '该URL暂无成功的参数测试结果';
                 }
             } else {
                 modalContent.textContent = '无法获取参数测试数据';
             }
             
             modal.style.display = 'block';
         }
         


        // 带认证访问的函数
         function accessWithAuth(url) {
             // 找到对应的认证请求数据
             const result = vulnerableResults.find(r => r.url === url);
             if (result) {
                 try {
                     // 解析认证请求，提取认证头
                     const authReq = JSON.parse(result.authRequest);
                     const headers = {};
                     
                     // 提取Cookie和Authorization等认证头
                     const lines = authReq.split('\\r\\n');
                     for (let line of lines) {
                         if (line.toLowerCase().startsWith('cookie:')) {
                             headers['Cookie'] = line.substring(7).trim();
                         } else if (line.toLowerCase().startsWith('authorization:')) {
                             headers['Authorization'] = line.substring(14).trim();
                         }
                     }
                     
                     // 使用fetch API发送带认证头的请求
                     fetch(url, {
                         method: 'GET',
                         headers: headers,
                         credentials: 'include'
                     }).then(response => {
                         if (response.ok) {
                             // 如果请求成功，在新窗口中打开
                             const newWindow = window.open('', '_blank');
                             response.text().then(text => {
                                 newWindow.document.write(text);
                                 newWindow.document.close();
                             });
                         } else {
                             alert('访问失败，状态码: ' + response.status);
                         }
                     }).catch(error => {
                         console.error('请求失败:', error);
                         // 如果fetch失败（可能是CORS问题），提示用户手动复制认证头
                         const authHeaders = Object.entries(headers).map(([k, v]) => k + ': ' + v).join('\\n');
                         alert('由于浏览器安全限制，无法自动带认证头访问。\\n\\n请手动在浏览器开发者工具中添加以下请求头：\\n' + authHeaders);
                         window.open(url, '_blank');
                     });
                 } catch (e) {
                     console.error('解析认证数据失败:', e);
                     window.open(url, '_blank');
                 }
             } else {
                 window.open(url, '_blank');
             }
         }

        // 关闭模态框
        function closeModal() {
            document.getElementById('requestModal').style.display = 'none';
        }

        // 点击模态框外部关闭
        window.onclick = function(event) {
            const modal = document.getElementById('requestModal');
            if (event.target === modal) {
                modal.style.display = 'none';
            }
        }
    </script>
</body>
</html>
`
