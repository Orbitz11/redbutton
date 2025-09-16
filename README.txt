<!DOCTYPE html>
<html lang="ar" dir="rtl">
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
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        body {
            background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
            color: #c9d1d9;
            line-height: 1.6;
            padding: 20px;
            min-height: 100vh;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            gap: 25px;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 0;
            border-bottom: 1px solid #21262d;
            flex-wrap: wrap;
        }
        .repo-title {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .repo-title h1 {
            font-size: 24px;
            font-weight: 600;
        }
        .repo-title span {
            color: #58a6ff;
        }
        .repo-buttons {
            display: flex;
            gap: 12px;
        }
        .btn {
            display: flex;
            align-items: center;
            gap: 6px;
            padding: 8px 16px;
            background-color: #21262d;
            border: 1px solid #363b42;
            border-radius: 6px;
            color: #c9d1d9;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .btn:hover {
            background-color: #30363d;
            border-color: #8b949e;
        }
        .btn i {
            font-size: 16px;
        }
        .btn-watch:hover {
            color: #58a6ff;
        }
        .btn-star:hover {
            color: #f0d66b;
        }
        .btn-fork:hover {
            color: #6ecc67;
        }
        .btn-count {
            padding-left: 10px;
            margin-left: 8px;
            position: relative;
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
            margin: 15px 0;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
        }
        .banner img {
            max-width: 100%;
            height: auto;
            display: block;
        }
        .badges {
            display: flex;
            justify-content: center;
            flex-wrap: wrap;
            gap: 10px;
            margin: 20px 0;
        }
        .badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            background: linear-gradient(90deg, #1f6feb 0%, #0d419d 100%);
            border-radius: 20px;
            font-size: 14px;
            color: #fff;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.2);
        }
        .badge i {
            font-size: 14px;
        }
        .content {
            display: grid;
            grid-template-columns: 1fr 350px;
            gap: 25px;
        }
        .main-content {
            background: linear-gradient(135deg, #161b22 0%, #0d1117 100%);
            border: 1px solid #21262d;
            border-radius: 12px;
            padding: 25px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        }
        .sidebar {
            display: flex;
            flex-direction: column;
            gap: 25px;
        }
        .card {
            background: linear-gradient(135deg, #161b22 0%, #0d1117 100%);
            border: 1px solid #21262d;
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        }
        .card h3 {
            font-size: 18px;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid #21262d;
            color: #58a6ff;
        }
        .about {
            margin-bottom: 25px;
        }
        .about h2 {
            font-size: 28px;
            margin-bottom: 20px;
            color: #f0f6fc;
        }
        .about p {
            margin-bottom: 20px;
            color: #8b949e;
            line-height: 1.8;
        }
        .setup, .run {
            margin-bottom: 25px;
        }
        .setup h2, .run h2 {
            font-size: 22px;
            margin-bottom: 20px;
            color: #f0f6fc;
        }
        .code-block {
            background-color: #0d1117;
            border: 1px solid #21262d;
            border-radius: 8px;
            padding: 18px;
            margin: 18px 0;
            overflow-x: auto;
            box-shadow: inset 0 2px 5px rgba(0, 0, 0, 0.2);
        }
        .code-block code {
            color: #c9d1d9;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 15px;
            line-height: 1.6;
        }
        .code-block .command {
            color: #7ee787;
        }
        .code-block .comment {
            color: #8b949e;
        }
        .stats {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }
        .stat-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
        }
        .stat-value {
            font-weight: 600;
            color: #f0f6fc;
        }
        .language-bar {
            height: 10px;
            background-color: #0d1117;
            border-radius: 10px;
            overflow: hidden;
            margin-top: 8px;
        }
        .language-fill {
            height: 100%;
            background: linear-gradient(90deg, #3572a5 0%, #2ea043 100%);
            border-radius: 10px;
        }
        .file {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 12px 0;
            border-bottom: 1px solid #21262d;
            transition: background-color 0.2s;
        }
        .file:hover {
            background-color: #1c2129;
            border-radius: 6px;
            padding-left: 10px;
            padding-right: 10px;
        }
        .file:last-child {
            border-bottom: none;
        }
        .file-icon {
            color: #7d8590;
            font-size: 18px;
        }
        .file-name {
            flex: 1;
            font-weight: 500;
        }
        .file-date {
            color: #7d8590;
            font-size: 13px;
        }
        .workflow-list {
            list-style: none;
        }
        .workflow-list li {
            padding: 12px 0;
            border-bottom: 1px solid #21262d;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .workflow-list li:last-child {
            border-bottom: none;
        }
        .workflow-list li::before {
            content: "•";
            color: #58a6ff;
            font-weight: bold;
            font-size: 18px;
        }
        .empty-state {
            color: #7d8590;
            font-style: italic;
            text-align: center;
            padding: 20px 0;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #21262d;
            color: #8b949e;
            font-size: 14px;
        }
        @media (max-width: 900px) {
            .content {
                grid-template-columns: 1fr;
            }
            .repo-buttons {
                width: 100%;
                justify-content: center;
                margin-top: 15px;
            }
        }
        @media (max-width: 600px) {
            .header {
                flex-direction: column;
                align-items: flex-start;
            }
            .repo-buttons {
                justify-content: flex-start;
            }
            .btn {
                padding: 8px 12px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="repo-title">
                <i class="fab fa-github fa-2x"></i>
                <h1>Orbitz11 / <span>redbutton</span></h1>
            </div>
            <div class="repo-buttons">
                <button class="btn btn-watch"><i class="far fa-eye"></i> Watch <span class="btn-count">0</span></button>
                <button class="btn btn-star"><i class="far fa-star"></i> Star <span class="btn-count">1</span></button>
                <button class="btn btn-fork"><i class="fas fa-code-branch"></i> Fork <span class="btn-count">0</span></button>
            </div>
        </div>

        <div class="banner">
            <img src="https://placehold.co/1000x400/161b22/7d8590/png?text=RedButton+Project+Banner" alt="RedButton Banner">
        </div>

        <div class="badges">
            <span class="badge"><i class="fas fa-user"></i> Action: Orbitz11</span>
            <span class="badge"><i class="fas fa-tag"></i> Version 1.5</span>
            <span class="badge"><i class="fas fa-tools"></i> Maintenance: Active</span>
            <span class="badge"><i class="fab fa-python"></i> Python</span>
            <span class="badge"><i class="fas fa-eye"></i> 11,897 visits</span>
        </div>

        <div class="content">
            <div class="main-content">
                <div class="about">
                    <h2>RedButton v1.5</h2>
                    <p>أداة قوية لاختبار الأمان ومهام إدارة النظام. يوفر RedButton مجموعة من الأدوات للمحترفين في مجال الأمن السيبراني وإدارة تكنولوجيا المعلومات.</p>
                    <p>تم تصميم هذه الأداة لتسهيل عملية اختبار الاختراق وإدارة الأنظمة مع واجهة سهلة الاستخدام.</p>
                </div>

                <div class="setup">
                    <h2>التثبيت والإعداد</h2>
                    <p>اتبع هذه الخطوات لتثبيت وتشغيل RedButton على نظامك:</p>
                    <div class="code-block">
                        <code>
                            <span class="command">git clone</span> https://github.com/Orbitz11/redbutton.git<br>
                            <span class="command">cd</span> redbutton<br>
                            <span class="command">php install r</span> requirements.txt
                        </code>
                    </div>
                </div>

                <div class="run">
                    <h2>التشغيل</h2>
                    <p>بعد الانتهاء من التثبيت، يمكنك تشغيل البرنامج باستخدام:</p>
                    <div class="code-block">
                        <code>
                            <span class="command">python</span> redbutton.py
                        </code>
                    </div>
                    <p>سيبدأ البرنامج بواجهة المستخدم الرسومية التي تتيح لك الوصول إلى جميع الميزات.</p>
                </div>
            </div>

            <div class="sidebar">
                <div class="card">
                    <h3>حول المشروع</h3>
                    <p>أداة اختبار أمان مكتوبة بلغة Python مع أدوات متنوعة لمسؤولي النظام.</p>
                </div>

                <div class="card">
                    <h3>ملفات المستودع</h3>
                    <div class="file">
                        <i class="far fa-file-code file-icon"></i>
                        <div class="file-name">update.json</div>
                        <div class="file-date">الشهر الماضي</div>
                    </div>
                    <div class="file">
                        <i class="far fa-file-code file-icon"></i>
                        <div class="file-name">update.json</div>
                        <div class="file-date">الشهر الماضي</div>
                    </div>
                    <div class="file">
                        <i class="far fa-file-alt file-icon"></i>
                        <div class="file-name">README</div>
                        <div class="file-date">الشهر الماضي</div>
                    </div>
                </div>

                <div class="card">
                    <h3>الإحصائيات</h3>
                    <div class="stats">
                        <div class="stat-item">
                            <span>النجوم:</span>
                            <span class="stat-value">1</span>
                        </div>
                        <div class="stat-item">
                            <span>المشاهدات:</span>
                            <span class="stat-value">0</span>
                        </div>
                        <div class="stat-item">
                            <span>النُسخ:</span>
                            <span class="stat-value">0</span>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <h3>الإصدارات</h3>
                    <p class="empty-state">لا توجد إصدارات منشورة</p>
                    <button class="btn" style="width: 100%; justify-content: center; margin-top: 10px;">
                        إنشاء إصدار جديد
                    </button>
                </div>

                <div class="card">
                    <h3>الحزم</h3>
                    <p class="empty-state">لا توجد حزم منشورة</p>
                </div>

                <div class="card">
                    <h3>اللغات المستخدمة</h3>
                    <div class="stat-item">
                        <span>Python</span>
                        <span class="stat-value">100.0%</span>
                    </div>
                    <div class="language-bar">
                        <div class="language-fill" style="width: 100%;"></div>
                    </div>
                </div>

                <div class="card">
                    <h3>سير العمل المقترحة</h3>
                    <p>بناءً على التقنيات المستخدمة</p>
                    <ul class="workflow-list">
                        <li>مولد SLSA العام</li>
                    </ul>
                </div>
            </div>
        </div>

        <div class="footer">
            <p>© 2023 Orbitz11/redbutton. جميع الحقوق محفوظة.</p>
            <p>يتم توزيع هذا المشروع بموجب ترخيص MIT.</p>
        </div>
    </div>

    <script>
        // تفاعلية الأزرار
        document.querySelectorAll('.btn-watch, .btn-star, .btn-fork').forEach(btn => {
            btn.addEventListener('click', function() {
                const countElement = this.querySelector('.btn-count');
                let count = parseInt(countElement.textContent);
                
                if (this.classList.contains('btn-star')) {
                    if (this.classList.contains('active')) {
                        count--;
                        this.classList.remove('active');
                        this.querySelector('i').classList.replace('fas', 'far');
                        this.style.color = '#c9d1d9';
                    } else {
                        count++;
                        this.classList.add('active');
                        this.querySelector('i').classList.replace('far', 'fas');
                        this.style.color = '#f0d66b';
                    }
                    countElement.textContent = count;
                } else if (this.classList.contains('btn-watch')) {
                    if (this.classList.contains('active')) {
                        count--;
                        this.classList.remove('active');
                        this.querySelector('i').classList.replace('fas', 'far');
                        this.style.color = '#c9d1d9';
                    } else {
                        count++;
                        this.classList.add('active');
                        this.querySelector('i').classList.replace('far', 'fas');
                        this.style.color = '#58a6ff';
                    }
                    countElement.textContent = count;
                } else if (this.classList.contains('btn-fork')) {
                    if (this.classList.contains('active')) {
                        count--;
                        this.classList.remove('active');
                        this.style.color = '#c9d1d9';
                    } else {
                        count++;
                        this.classList.add('active');
                        this.style.color = '#6ecc67';
                    }
                    countElement.textContent = count;
                }
            });
        });

        // تأثيرات عند التمرير
        window.addEventListener('scroll', () => {
            const cards = document.querySelectorAll('.card');
            cards.forEach(card => {
                const cardTop = card.getBoundingClientRect().top;
                const windowHeight = window.innerHeight;
                if (cardTop < windowHeight * 0.9) {
                    card.style.opacity = '1';
                    card.style.transform = 'translateY(0)';
                }
            });
        });

        // تهيئة تأثيرات التمرير
        document.querySelectorAll('.card').forEach(card => {
            card.style.opacity = '0';
            card.style.transform = 'translateY(20px)';
            card.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
        });

        // تشغيل تأثيرات التمرير عند التحميل
        window.dispatchEvent(new Event('scroll'));
    </script>
</body>
</html>
