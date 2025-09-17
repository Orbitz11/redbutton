<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Orbitz11/redbutton - GitHub Repository</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
        }
        body {
            background-color: #0d1117;
            color: #c9d1d9;
            line-height: 1.5;
            padding: 20px;
            max-width: 1280px;
            margin: 0 auto;
        }
        .container {
            display: flex;
            flex-direction: column;
            gap: 20px;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 16px;
            border-bottom: 1px solid #21262d;
        }
        .repo-title {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .repo-title h1 {
            font-size: 20px;
            font-weight: 600;
        }
        .repo-title span {
            color: #7d8590;
        }
        .repo-buttons {
            display: flex;
            gap: 10px;
        }
        .btn {
            display: flex;
            align-items: center;
            gap: 4px;
            padding: 5px 16px;
            background-color: #21262d;
            border: 1px solid #363b42;
            border-radius: 6px;
            color: #c9d1d9;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
        }
        .btn:hover {
            background-color: #30363d;
            border-color: #8b949e;
        }
        .btn-watch, .btn-star, .btn-fork {
            position: relative;
        }
        .btn-count {
            position: relative;
            padding-left: 12px;
            margin-left: 6px;
        }
        .btn-count::before {
            content: "";
            position: absolute;
            left: 0;
            top: 50%;
            transform: translateY(-50%);
            height: 60%;
            width: 1px;
            background-color: #363b42;
        }
        .banner {
            text-align: center;
            margin: 20px 0;
        }
        .banner img {
            max-width: 800px;
            width: 100%;
            border-radius: 6px;
            border: 1px solid #30363d;
        }
        .badges {
            display: flex;
            justify-content: center;
            flex-wrap: wrap;
            gap: 8px;
            margin: 20px 0;
        }
        .badge {
            display: inline-flex;
            align-items: center;
            padding: 5px 10px;
            background-color: #21262d;
            border-radius: 4px;
            font-size: 14px;
            color: #c9d1d9;
            border: 1px solid #363b42;
        }
        .developer-info {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 15px;
            margin: 15px 0;
            padding: 15px;
            background: linear-gradient(90deg, #161b22, #0d1117);
            border-radius: 8px;
            border: 1px solid #21262d;
        }
        .developer-avatar {
            width: 60px;
            height: 60px;
            border-radius: 50%;
            border: 2px solid #58a6ff;
            overflow: hidden;
        }
        .developer-avatar img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }
        .developer-details {
            display: flex;
            flex-direction: column;
        }
        .developer-name {
            font-weight: bold;
            color: #58a6ff;
            font-size: 18px;
        }
        .developer-role {
            color: #7d8590;
            font-size: 14px;
        }
        .version-info {
            text-align: center;
            margin: 15px 0;
            padding: 12px;
            background: linear-gradient(90deg, #0d1117, #161b22);
            border-radius: 8px;
            border: 1px solid #21262d;
        }
        .version-title {
            font-size: 16px;
            color: #7ee787;
            margin-bottom: 5px;
        }
        .version-number {
            font-size: 24px;
            font-weight: bold;
            color: #f0f6fc;
        }
        .version-date {
            font-size: 14px;
            color: #7d8590;
            margin-top: 5px;
        }
        .content {
            display: grid;
            grid-template-columns: 1fr 300px;
            gap: 20px;
        }
        .main-content {
            background-color: #161b22;
            border: 1px solid #21262d;
            border-radius: 6px;
            padding: 20px;
        }
        .sidebar {
            display: flex;
            flex-direction: column;
            gap: 20px;
        }
        .card {
            background-color: #161b22;
            border: 1px solid #21262d;
            border-radius: 6px;
            padding: 16px;
        }
        .card h3 {
            font-size: 16px;
            margin-bottom: 12px;
            padding-bottom: 8px;
            border-bottom: 1px solid #21262d;
        }
        .about {
            margin-bottom: 20px;
        }
        .about h2 {
            font-size: 24px;
            margin-bottom: 16px;
        }
        .about p {
            margin-bottom: 16px;
            color: #8b949e;
        }
        .setup {
            margin-bottom: 20px;
        }
        .setup h2 {
            font-size: 20px;
            margin-bottom: 16px;
        }
        .code-block {
            background-color: #0d1117;
            border: 1px solid #21262d;
            border-radius: 6px;
            padding: 16px;
            margin: 16px 0;
            overflow-x: auto;
        }
        .code-block code {
            color: #c9d1d9;
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            font-size: 14px;
        }
        .code-block .command {
            color: #7ee787;
        }
        .stats {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .stat-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .stat-value {
            font-weight: 600;
        }
        .language-bar {
            height: 8px;
            background-color: #0d1117;
            border-radius: 6px;
            overflow: hidden;
            margin-top: 4px;
        }
        .language-fill {
            height: 100%;
            background-color: #3572a5;
        }
        .file {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 0;
            border-bottom: 1px solid #21262d;
        }
        .file:last-child {
            border-bottom: none;
        }
        .file-icon {
            color: #7d8590;
        }
        .file-name {
            flex: 1;
        }
        .file-date {
            color: #7d8590;
            font-size: 12px;
        }
        .workflow-list {
            list-style: none;
        }
        .workflow-list li {
            padding: 8px 0;
            border-bottom: 1px solid #21262d;
        }
        .workflow-list li:last-child {
            border-bottom: none;
        }
        .empty-state {
            color: #7d8590;
            font-style: italic;
        }
        @media (max-width: 768px) {
            .content {
                grid-template-columns: 1fr;
            }
            .repo-buttons {
                flex-wrap: wrap;
            }
            .developer-info {
                flex-direction: column;
                text-align: center;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="repo-title">
                <i class="fab fa-github"></i>
                <h1>Orbitz11 / <span>redbutton</span></h1>
            </div>
            <div class="repo-buttons">
                <button class="btn btn-watch"><i class="far fa-eye"></i> Watch <span class="btn-count">0</span></button>
                <button class="btn btn-star"><i class="far fa-star"></i> Star <span class="btn-count">1</span></button>
                <button class="btn btn-fork"><i class="fas fa-code-branch"></i> Fork <span class="btn-count">0</span></button>
            </div>
        </div>

        <div class="banner">
            <img src="https://placehold.co/800x300/161b22/7d8590/png?text=RedButton+Project+Banner" alt="RedButton Banner">
        </div>

        <div class="badges">
            <span class="badge"><i class="fas fa-user"></i> Action: Orbitz11</span>
            <span class="badge"><i class="fas fa-tag"></i> Version 1.5</span>
            <span class="badge"><i class="fas fa-tools"></i> Maintenance: Active</span>
            <span class="badge"><i class="fab fa-python"></i> Python</span>
            <span class="badge"><i class="fas fa-eye"></i> 11,897 visits</span>
        </div>

        <!-- معلومات المبرمج -->
        <div class="developer-info">
            <div class="developer-avatar">
                <img src="https://placehold.co/100x100/161b22/58a6ff/png?text=O" alt="Developer Avatar">
            </div>
            <div class="developer-details">
                <div class="developer-name">Orbitz11</div>
                <div class="developer-role">مطور ومبرمج المشروع</div>
            </div>
        </div>

        <!-- معلومات الاصدار -->
        <div class="version-info">
            <div class="version-title">الإصدار الحالي</div>
            <div class="version-number">v1.5</div>
            <div class="version-date">تم التحديث في: 15 نوفمبر 2023</div>
        </div>

        <div class="content">
            <div class="main-content">
                <div class="about">
                    <h2>RedButton v1.5</h2>
                    <p>A powerful utility tool for security testing and system administration tasks. RedButton provides a suite of tools for professionals in cybersecurity and IT administration.</p>
                    <p>تم تطويره بواسطة Orbitz11، هذا المشروع مخصص لاختبار الأمان وإدارة النظام مع واجهة سهلة الاستخدام.</p>
                </div>

                <div class="setup">
                    <h2>Setup</h2>
                    <div class="code-block">
                        <code>
                            <span class="command">git clone</span> https://github.com/Orbitz11/redbutton.git<br>
                            <span class="command">cd</span> redbutton<br>
                            <span class="command">php install r</span> requirements.txt
                        </code>
                    </div>
                </div>

                <div class="run">
                    <h2>Run</h2>
                    <div class="code-block">
                        <code>
                            <span class="command">python</span> redbutton.py
                        </code>
                    </div>
                </div>
            </div>

            <div class="sidebar">
                <div class="card">
                    <h3>About</h3>
                    <p>A security testing tool written in Python with various utilities for system administrators.</p>
                    <p>تم تطويره بواسطة: <strong>Orbitz11</strong></p>
                    <p>الإصدار: <strong>1.5</strong></p>
                </div>

                <div class="card">
                    <h3>Repository files</h3>
                    <div class="file">
                        <i class="far fa-file-code file-icon"></i>
                        <div class="file-name">update.json</div>
                        <div class="file-date">last month</div>
                    </div>
                    <div class="file">
                        <i class="far fa-file-code file-icon"></i>
                        <div class="file-name">update.json</div>
                        <div class="file-date">last month</div>
                    </div>
                    <div class="file">
                        <i class="far fa-file-alt file-icon"></i>
                        <div class="file-name">README</div>
                        <div class="file-date">last month</div>
                    </div>
                </div>

                <div class="card">
                    <h3>Statistics</h3>
                    <div class="stats">
                        <div class="stat-item">
                            <span>Stars:</span>
                            <span class="stat-value">1</span>
                        </div>
                        <div class="stat-item">
                            <span>Watching:</span>
                            <span class="stat-value">0</span>
                        </div>
                        <div class="stat-item">
                            <span>Forks:</span>
                            <span class="stat-value">0</span>
                        </div>
                        <div class="stat-item">
                            <span>المبرمج:</span>
                            <span class="stat-value">Orbitz11</span>
                        </div>
                        <div class="stat-item">
                            <span>الإصدار:</span>
                            <span class="stat-value">1.5</span>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <h3>Releases</h3>
                    <p class="empty-state">No releases published</p>
                    <button class="btn" style="width: 100%; justify-content: center; margin-top: 10px;">
                        Create a new release
                    </button>
                </div>

                <div class="card">
                    <h3>Packages</h3>
                    <p class="empty-state">No packages published</p>
                </div>

                <div class="card">
                    <h3>Languages</h3>
                    <div class="stat-item">
                        <span>Python</span>
                        <span class="stat-value">100.0%</span>
                    </div>
                    <div class="language-bar">
                        <div class="language-fill" style="width: 100%;"></div>
                    </div>
                </div>

                <div class="card">
                    <h3>Suggested workflows</h3>
                    <p>Based on your tech stack</p>
                    <ul class="workflow-list">
                        <li>SLSA Generic generator</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Simple interactivity for buttons
        document.querySelectorAll('.btn-watch, .btn-star, .btn-fork').forEach(btn => {
            btn.addEventListener('click', function() {
                const countElement = this.querySelector('.btn-count');
                let count = parseInt(countElement.textContent);
                
                if (this.classList.contains('btn-star')) {
                    if (this.classList.contains('active')) {
                        count--;
                        this.classList.remove('active');
                        this.querySelector('i').classList.replace('fas', 'far');
                    } else {
                        count++;
                        this.classList.add('active');
                        this.querySelector('i').classList.replace('far', 'fas');
                    }
                    countElement.textContent = count;
                } else if (this.classList.contains('btn-watch')) {
                    if (this.classList.contains('active')) {
                        count--;
                        this.classList.remove('active');
                        this.querySelector('i').classList.replace('fas', 'far');
                    } else {
                        count++;
                        this.classList.add('active');
                        this.querySelector('i').classList.replace('far', 'fas');
                    }
                    countElement.textContent = count;
                }
            });
        });
    </script>
</body>
</html>
