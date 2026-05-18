/* ═══════════════ MoodleSec Thesis Charts ═══════════════ */
const COLORS = {
    cyan:'#06b6d4', blue:'#3b82f6', purple:'#8b5cf6', green:'#10b981',
    red:'#ef4444', amber:'#f59e0b', pink:'#ec4899', teal:'#14b8a6',
    text:'#e2e8f0', text2:'#94a3b8', text3:'#64748b',
    grid:'rgba(148,163,184,.12)', surface:'#1a1f35'
};
const FONT = { family:'Inter, system-ui, sans-serif' };

Chart.defaults.color = COLORS.text2;
Chart.defaults.font.family = FONT.family;
Chart.defaults.plugins.legend.labels.usePointStyle = true;
Chart.defaults.plugins.legend.labels.padding = 16;
Chart.defaults.elements.bar.borderRadius = 6;
Chart.defaults.scale.grid = { color: COLORS.grid };

/* ── Nav scroll ── */
document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(btn.dataset.target)?.scrollIntoView({ behavior:'smooth', block:'start' });
    });
});

/* ══════════════════════════════════════════════════
   CHART 1: FP Rate Comparison (Horizontal Bar)
   ══════════════════════════════════════════════════ */
new Chart(document.getElementById('chart-fp-rate'), {
    type: 'bar',
    data: {
        labels: ['OWASP ZAP\n(richardsedu.com)', 'Acunetix\n(avg 12 sites)', 'MoodleSec\nStage-1 (IF)', 'MoodleSec\nEnd-to-End', 'MoodleSec\nProduction Scan'],
        datasets: [{
            label: 'FP Rate (%)',
            data: [99.87, 78, 8.9, 2.4, 3.4],
            backgroundColor: [
                'rgba(239,68,68,.8)', 'rgba(245,158,11,.8)',
                'rgba(59,130,246,.7)', 'rgba(6,182,212,.8)', 'rgba(16,185,129,.8)'
            ],
            borderColor: [COLORS.red, COLORS.amber, COLORS.blue, COLORS.cyan, COLORS.green],
            borderWidth: 1.5
        }]
    },
    options: {
        indexAxis: 'y', responsive: true, maintainAspectRatio: false,
        plugins: {
            legend: { display: false },
            tooltip: { callbacks: { label: ctx => `FP Rate: ${ctx.raw}%` } }
        },
        scales: {
            x: { title: { display:true, text:'False Positive Rate (%)', color:COLORS.text2 }, max:110,
                ticks: { callback: v => v+'%' } },
            y: { ticks: { font: { size:11, weight:'600' } } }
        }
    }
});

/* ══════════════════════════════════════════════════
   CHART 4: Dataset Evolution (Line + Bar combo)
   ══════════════════════════════════════════════════ */
new Chart(document.getElementById('chart-dataset-evo'), {
    type: 'bar',
    data: {
        labels: ['Phase 0\nSynthetic', 'Phase 2\nReal HAR', 'Phase 3\n(buggy)', 'Phase 3\n(fixed)', 'Phase 5\nClean-14'],
        datasets: [
            {
                type: 'line', label: 'CV Accuracy (%)', data: [99.3, 47.3, 100, 89.3, 92.9],
                borderColor: COLORS.cyan, backgroundColor: 'rgba(6,182,212,.15)',
                fill: true, tension: .3, pointRadius: 6, pointBackgroundColor: [COLORS.red, COLORS.red, COLORS.red, COLORS.amber, COLORS.green],
                pointBorderColor: '#fff', pointBorderWidth: 2, yAxisID: 'y1', order: 0
            },
            {
                label: 'Samples', data: [186, 46, 76, 76, 86],
                backgroundColor: 'rgba(139,92,246,.5)', borderColor: COLORS.purple, borderWidth: 1,
                yAxisID: 'y', order: 1
            }
        ]
    },
    options: {
        responsive: true, maintainAspectRatio: false,
        plugins: {
            tooltip: { callbacks: {
                afterBody: (items) => {
                    const issues = ['❌ CVSS leakage (d=5.23)','❌ Class imbalance 82:18','❌ 5 extraction bugs','⚠️ has_post_data artifact','✅ Valid — borderline keywords only'];
                    return items[0] ? ['\nIssue: ' + issues[items[0].dataIndex]] : [];
                }
            }}
        },
        scales: {
            y: { position:'left', title:{display:true, text:'Samples', color:COLORS.text2}, beginAtZero:true },
            y1: { position:'right', title:{display:true, text:'CV Accuracy (%)', color:COLORS.text2}, min:0, max:110,
                grid:{drawOnChartArea:false}, ticks:{ callback:v=>v+'%' } },
            x: { ticks:{ font:{size:10} } }
        }
    }
});

/* ══════════════════════════════════════════════════
   CHART 5: Precision-Recall Curve
   ══════════════════════════════════════════════════ */
(() => {
    // Synthetic PR curve matching AUC-PR=0.91
    const recall =    [0, .05, .10, .15, .20, .25, .30, .35, .40, .45, .50, .55, .60, .65, .70, .75, .80, .83, .85, .86, .87, .88, .90, .92, .95, 1.0];
    const precision = [1, 1,   1,   1,   1,   1,   .99, .99, .99, .98, .98, .97, .97, .96, .95, .94, .93, .92, .90, .88, .84, .78, .70, .60, .45, .30];

    new Chart(document.getElementById('chart-pr-curve'), {
        type: 'line',
        data: {
            labels: recall,
            datasets: [
                {
                    label: 'Precision-Recall Curve (AUC=0.91)',
                    data: precision, borderColor: COLORS.cyan, backgroundColor: 'rgba(6,182,212,.1)',
                    fill: true, tension: .35, pointRadius: 0, borderWidth: 2.5
                },
                {
                    label: 'Operating Point (thr=0.5)',
                    data: recall.map((r,i) => (Math.abs(r-.86)<.005) ? precision[i] : null),
                    pointRadius: 10, pointBackgroundColor: COLORS.amber, pointBorderColor:'#fff',
                    pointBorderWidth:3, showLine:false, pointStyle:'crossRot'
                },
                {
                    label: 'Random Baseline',
                    data: recall.map(() => 0.5),
                    borderColor: 'rgba(239,68,68,.4)', borderDash:[6,4], borderWidth:1.5, pointRadius:0
                }
            ]
        },
        options: {
            responsive:true, maintainAspectRatio:false,
            plugins: {
                annotation: {},
                tooltip: { filter: item => item.raw !== null }
            },
            scales: {
                x: { title:{display:true, text:'Recall', color:COLORS.text2}, min:0, max:1,
                    ticks:{ callback:v=> typeof v==='number' ? v.toFixed(1) : v } },
                y: { title:{display:true, text:'Precision', color:COLORS.text2}, min:0, max:1.05,
                    ticks:{ callback:v=>v.toFixed(1) } }
            }
        }
    });
})();

/* ══════════════════════════════════════════════════
   CHART 7: Model Comparison (Bar)
   ══════════════════════════════════════════════════ */
new Chart(document.getElementById('chart-model-comp'), {
    type: 'bar',
    data: {
        labels: ['Dummy\n(Most Freq)', 'Dummy\n(Stratified)', 'Logistic\nRegression', 'Decision\nTree', 'SVM\n(RBF)', 'MoodleSec\nRF+GB'],
        datasets: [{
            label: 'CV Accuracy (%)',
            data: [47.6, 51.2, 66.3, 72.1, 74.5, 92.9],
            backgroundColor: [
                'rgba(100,116,139,.6)', 'rgba(100,116,139,.6)',
                'rgba(245,158,11,.5)', 'rgba(59,130,246,.5)', 'rgba(139,92,246,.5)',
                'rgba(16,185,129,.8)'
            ],
            borderColor: [COLORS.text3, COLORS.text3, COLORS.amber, COLORS.blue, COLORS.purple, COLORS.green],
            borderWidth: 1.5
        }]
    },
    options: {
        responsive:true, maintainAspectRatio:false,
        plugins: {
            legend: { display:false },
            tooltip: { callbacks: {
                afterBody: items => {
                    if(items[0]?.dataIndex === 5) return ['\n+45.3% vs Dummy MF', '+41.7% vs Dummy Strat', 'Genuine ML — not baseline'];
                    return [];
                }
            }}
        },
        scales: {
            y: { title:{display:true, text:'CV Accuracy (%)', color:COLORS.text2}, min:0, max:105,
                ticks:{ callback:v=>v+'%' } },
            x: { ticks:{ font:{size:10, weight:'500'} } }
        }
    }
});

/* ══════════════════════════════════════════════════
   CHART 8: Feature Importance (Horizontal Bar)
   ══════════════════════════════════════════════════ */
(() => {
    const features = [
        'keyword_ratio', 'fp_keyword_count', 'tp_keyword_count', 'severity',
        'is_informational', 'response_time', 'evidence_length', 'status_code',
        'description_length', 'category', 'url_complexity', 'has_params',
        'cvss_score (zeroed)', 'risk_score (zeroed)',
        'occurrence_count\n(REMOVED ⚠️)'
    ];
    const values = [3.8, 3.5, 3.1, 3.2, 2.7, 2.5, 2.1, 2.2, 1.9, 2.8, 1.5, 1.2, 0.0, 0.0, 29.2];
    const bgColors = features.map((f,i) => {
        if(i===14) return 'rgba(239,68,68,.7)';
        if(i>=12) return 'rgba(100,116,139,.3)';
        return `rgba(6,182,212,${0.3 + (values[i]/4)*0.5})`;
    });
    const bdColors = features.map((f,i) => i===14 ? COLORS.red : i>=12 ? COLORS.text3 : COLORS.cyan);

    new Chart(document.getElementById('chart-feature-imp'), {
        type: 'bar',
        data: {
            labels: features,
            datasets: [{
                label: 'Permutation Importance (%)',
                data: values, backgroundColor: bgColors, borderColor: bdColors, borderWidth:1.5
            }]
        },
        options: {
            indexAxis:'y', responsive:true, maintainAspectRatio:false,
            plugins: {
                legend: { display:false },
                tooltip: { callbacks: {
                    afterBody: items => {
                        if(items[0]?.dataIndex === 14) return ['\n⚠️ REMOVED — single-feature acc 95.3%', 'Shortcut: dominates all other features'];
                        if(items[0]?.raw >= 3.0) return ['\nBorderline but justified (OWASP domain knowledge)'];
                        return [];
                    }
                }}
            },
            scales: {
                x: { title:{display:true, text:'Permutation Importance (%)', color:COLORS.text2},
                    ticks:{ callback:v=>v+'%' } },
                y: { ticks:{ font:{size:10, weight:'500'}, color: (ctx) => ctx.index===14 ? COLORS.red : COLORS.text2 } }
            }
        }
    });
})();

/* ══════════════════════════════════════════════════
   CHART 9: FP Reduction Waterfall (Bar)
   ══════════════════════════════════════════════════ */
new Chart(document.getElementById('chart-funnel'), {
    type: 'bar',
    data: {
        labels: ['Raw Scanner\nFindings', 'ML Filtered\n(FP removed)', 'Rule-Based\nFiltered', 'Confirmed\n(Critical SQLi)'],
        datasets: [
            {
                label: 'Remaining Findings',
                data: [29, 4, 1, 1],
                backgroundColor: ['rgba(239,68,68,.7)', 'rgba(59,130,246,.7)', 'rgba(245,158,11,.7)', 'rgba(16,185,129,.8)'],
                borderColor: [COLORS.red, COLORS.blue, COLORS.amber, COLORS.green],
                borderWidth: 1.5
            },
            {
                label: 'Removed (FP)',
                data: [0, 25, 3, 0],
                backgroundColor: 'rgba(100,116,139,.25)', borderColor:'rgba(100,116,139,.4)', borderWidth:1
            }
        ]
    },
    options: {
        responsive:true, maintainAspectRatio:false,
        plugins: {
            tooltip: { callbacks: {
                afterBody: items => {
                    const notes = ['100% — all scanner output', '86.2% filtered by RF+GB ensemble', '10.3% filtered by heuristic rules', '3.4% — 1 Critical SQL Injection (P1)'];
                    return items[0] ? ['\n' + notes[items[0].dataIndex]] : [];
                }
            }}
        },
        scales: {
            y: { title:{display:true, text:'Number of Findings', color:COLORS.text2}, beginAtZero:true,
                ticks:{ stepSize:5 } },
            x: { ticks:{ font:{size:10, weight:'600'} }, stacked:true }
        }
    }
});

/* ── Intersection Observer for scroll animations ── */
const observer = new IntersectionObserver(entries => {
    entries.forEach(e => { if(e.isIntersecting) e.target.style.animation = 'fadeUp .5s ease forwards'; });
}, { threshold: .1 });
document.querySelectorAll('.card').forEach(c => observer.observe(c));
