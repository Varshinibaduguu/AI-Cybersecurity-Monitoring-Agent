// Dashboard JavaScript for Cybersecurity Monitoring

// Global variables for charts
let threatTrendChart, threatTypeChart, riskScoreChart, loginStatsChart;

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', function() {
    initializeCharts();
    initializeNetworkCharts();
    loadDashboardData();
    setupEventListeners();
    
    // Auto-refresh dashboard every 30 seconds
    setInterval(loadDashboardData, 30000);
});

// Initialize all charts
function initializeCharts() {
    // Threat Trend Chart (Line Chart)
    const threatTrendCtx = document.getElementById('threatTrendChart').getContext('2d');
    threatTrendChart = new Chart(threatTrendCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Threat Count',
                data: [],
                borderColor: 'rgb(102, 126, 234)',
                backgroundColor: 'rgba(102, 126, 234, 0.1)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: false,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    position: 'top'
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            }
        }
    });

    // Threat Type Distribution Chart (Pie Chart)
    const threatTypeCtx = document.getElementById('threatTypeChart').getContext('2d');
    threatTypeChart = new Chart(threatTypeCtx, {
        type: 'pie',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    '#FF6384',
                    '#36A2EB',
                    '#FFCE56',
                    '#4BC0C0',
                    '#9966FF',
                    '#FF9F40'
                ],
                borderWidth: 2,
                borderColor: '#fff'
            }]
        },
        options: {
            responsive: false,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right'
                }
            }
        }
    });

    // Risk Score by User Chart (Bar Chart)
    const riskScoreCtx = document.getElementById('riskScoreChart').getContext('2d');
    riskScoreChart = new Chart(riskScoreCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Risk Score',
                data: [],
                backgroundColor: 'rgba(102, 126, 234, 0.8)',
                borderColor: 'rgb(102, 126, 234)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: false,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100
                }
            }
        }
    });

    // Failed vs Successful Logins Chart (Bar Chart)
    const loginStatsCtx = document.getElementById('loginStatsChart').getContext('2d');
    loginStatsChart = new Chart(loginStatsCtx, {
        type: 'bar',
        data: {
            labels: ['Failed Logins', 'Successful Logins'],
            datasets: [{
                label: 'Count',
                data: [0, 0],
                backgroundColor: [
                    'rgba(255, 99, 132, 0.8)',
                    'rgba(75, 192, 192, 0.8)'
                ],
                borderColor: [
                    'rgb(255, 99, 132)',
                    'rgb(75, 192, 192)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: false,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

// Load dashboard data from API
async function loadDashboardData() {
    try {
        const response = await fetch('/api/dashboard_data');
        const data = await response.json();
        
        if (data.error) {
            console.error('Error loading dashboard data:', data.error);
            return;
        }
        
        // Update summary cards
        updateSummaryCards(data);
        
        // Update charts
        updateCharts(data);
        
        // Update threat table
        updateThreatTable(data.recent_threats);
        
    } catch (error) {
        console.error('Error loading dashboard data:', error);
    }
}

// Update summary cards
function updateSummaryCards(data) {
    document.getElementById('totalThreats').textContent = data.total_threats || 0;
    document.getElementById('highRisk').textContent = data.high_risk || 0;
    document.getElementById('mediumRisk').textContent = data.medium_risk || 0;
    document.getElementById('systemStatus').textContent = data.system_status || 'Active';
}

// Update all charts
function updateCharts(data) {
    // Update Threat Trend Chart
    updateThreatTrendChart(data.all_logs);
    
    // Update Threat Type Distribution Chart
    updateThreatTypeChart(data.threat_types);
    
    // Update Risk Score by User Chart
    updateRiskScoreChart(data.all_logs);
    
    // Update Login Stats Chart
    updateLoginStatsChart(data.all_logs);
}

// Update Threat Trend Chart
function updateThreatTrendChart(logs) {
    if (!logs || logs.length === 0) return;
    
    // Group logs by hour
    const hourlyData = {};
    const now = new Date();
    
    // Initialize last 24 hours
    for (let i = 23; i >= 0; i--) {
        const hour = new Date(now - i * 60 * 60 * 1000);
        const key = hour.getHours().toString().padStart(2, '0') + ':00';
        hourlyData[key] = 0;
    }
    
    // Count threats per hour
    logs.forEach(log => {
        const timestamp = new Date(log.timestamp);
        const key = timestamp.getHours().toString().padStart(2, '0') + ':00';
        if (hourlyData.hasOwnProperty(key)) {
            hourlyData[key]++;
        }
    });
    
    threatTrendChart.data.labels = Object.keys(hourlyData);
    threatTrendChart.data.datasets[0].data = Object.values(hourlyData);
    threatTrendChart.update();
}

// Update Threat Type Distribution Chart
function updateThreatTypeChart(threatTypes) {
    if (!threatTypes) return;
    
    threatTypeChart.data.labels = Object.keys(threatTypes);
    threatTypeChart.data.datasets[0].data = Object.values(threatTypes);
    threatTypeChart.update();
}

// Update Risk Score by User Chart
function updateRiskScoreChart(logs) {
    if (!logs || logs.length === 0) return;
    
    // Calculate average risk score per user
    const userRiskScores = {};
    
    logs.forEach(log => {
        const user = log.user || 'Unknown';
        if (!userRiskScores[user]) {
            userRiskScores[user] = {
                total: 0,
                count: 0
            };
        }
        userRiskScores[user].total += log.risk_score || 0;
        userRiskScores[user].count++;
    });
    
    // Calculate averages
    const userAverages = {};
    Object.keys(userRiskScores).forEach(user => {
        userAverages[user] = Math.round(
            userRiskScores[user].total / userRiskScores[user].count
        );
    });
    
    // Sort by risk score and take top 10
    const sortedUsers = Object.entries(userAverages)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);
    
    riskScoreChart.data.labels = sortedUsers.map(([user]) => user);
    riskScoreChart.data.datasets[0].data = sortedUsers.map(([, score]) => score);
    riskScoreChart.update();
}

// Update Login Stats Chart
function updateLoginStatsChart(logs) {
    if (!logs || logs.length === 0) return;
    
    let failedLogins = 0;
    let successfulLogins = 0;
    
    logs.forEach(log => {
        if (log.threat_type === 'Brute Force Attack' || 
            log.threat_type === 'Suspicious Login') {
            failedLogins++;
        } else if (log.threat_type === 'Normal Activity') {
            successfulLogins++;
        }
    });
    
    loginStatsChart.data.datasets[0].data = [failedLogins, successfulLogins];
    loginStatsChart.update();
}

// Update threat table
function updateThreatTable(threats) {
    const tbody = document.getElementById('threatTableBody');
    tbody.innerHTML = '';
    
    if (!threats || threats.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center">No threats detected</td></tr>';
        return;
    }
    
    threats.forEach(threat => {
        const row = document.createElement('tr');
        const severityClass = `severity-${threat.severity.toLowerCase()}`;
        const timestamp = new Date(threat.timestamp).toLocaleString();
        
        row.innerHTML = `
            <td>${threat.user || 'Unknown'}</td>
            <td>${threat.threat_type}</td>
            <td>${threat.risk_score || 0}</td>
            <td><span class="severity-badge ${severityClass}">${threat.severity}</span></td>
            <td>${timestamp}</td>
        `;
        
        tbody.appendChild(row);
    });
}

// Setup event listeners
function setupEventListeners() {
    // Login Analysis Form
    document.getElementById('loginAnalysisForm').addEventListener('submit', handleLoginAnalysis);
    
    // Email Analysis Form
    document.getElementById('emailAnalysisForm').addEventListener('submit', handleEmailAnalysis);
    
    // File Analysis Form
    document.getElementById('fileAnalysisForm').addEventListener('submit', handleFileAnalysis);
    
    // File selection display
    document.getElementById('fileUpload').addEventListener('change', displaySelectedFiles);
    
    // Network control buttons
    const startBtn = document.getElementById('startNetworkBtn');
    const stopBtn = document.getElementById('stopNetworkBtn');
    
    if (startBtn) {
        startBtn.addEventListener('click', startNetworkMonitoring);
    }
    
    if (stopBtn) {
        stopBtn.addEventListener('click', stopNetworkMonitoring);
    }
}

// Handle login analysis
async function handleLoginAnalysis(event) {
    event.preventDefault();
    
    const loading = document.getElementById('loginLoading');
    const result = document.getElementById('loginResult');
    
    // Show loading
    loading.style.display = 'block';
    result.innerHTML = '';
    
    try {
        const formData = {
            user_id: document.getElementById('userId').value,
            login_time: document.getElementById('loginTime').value,
            failed_attempts: parseInt(document.getElementById('failedAttempts').value),
            country: document.getElementById('country').value,
            ip_address: document.getElementById('ipAddress').value
        };
        
        const response = await fetch('/api/analyze_login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formData)
        });
        
        const data = await response.json();
        
        if (data.error) {
            throw new Error(data.error);
        }
        
        // Display result
        displayLoginResult(data);
        
        // Refresh dashboard data
        setTimeout(loadDashboardData, 1000);
        
    } catch (error) {
        result.innerHTML = `
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-triangle"></i> Error: ${error.message}
            </div>
        `;
    } finally {
        loading.style.display = 'none';
    }
}

// Display login analysis result
function displayLoginResult(data) {
    const result = document.getElementById('loginResult');
    const severityClass = `severity-${data.severity.toLowerCase()}`;
    
    result.innerHTML = `
        <div class="result-card">
            <h5><i class="fas fa-shield-alt"></i> Login Analysis Result</h5>
            <div class="row">
                <div class="col-md-6">
                    <p><strong>Threat Type:</strong> ${data.threat_type}</p>
                    <p><strong>Risk Score:</strong> ${data.risk_score}/100</p>
                    <p><strong>Severity:</strong> <span class="severity-badge ${severityClass}">${data.severity}</span></p>
                </div>
                <div class="col-md-6">
                    <p><strong>Anomaly Detected:</strong> ${data.is_anomaly ? 'Yes' : 'No'}</p>
                    <p><strong>Confidence:</strong> ${(data.confidence * 100).toFixed(1)}%</p>
                </div>
            </div>
        </div>
    `;
}

// Handle email analysis
async function handleEmailAnalysis(event) {
    event.preventDefault();
    
    const loading = document.getElementById('emailLoading');
    const result = document.getElementById('emailResult');
    
    // Show loading
    loading.style.display = 'block';
    result.innerHTML = '';
    
    try {
        const formData = {
            user_id: document.getElementById('emailUserId').value,
            email_content: document.getElementById('emailContent').value
        };
        
        const response = await fetch('/api/analyze_email', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formData)
        });
        
        const data = await response.json();
        
        if (data.error) {
            throw new Error(data.error);
        }
        
        // Display result
        displayEmailResult(data);
        
        // Refresh dashboard data
        setTimeout(loadDashboardData, 1000);
        
    } catch (error) {
        result.innerHTML = `
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-triangle"></i> Error: ${error.message}
            </div>
        `;
    } finally {
        loading.style.display = 'none';
    }
}

// Display email analysis result
function displayEmailResult(data) {
    const result = document.getElementById('emailResult');
    const severityClass = `severity-${data.severity.toLowerCase()}`;
    
    let featuresHtml = '';
    if (data.features) {
        featuresHtml = `
            <div class="mt-3">
                <h6>Analysis Features:</h6>
                <div class="row">
                    <div class="col-md-6">
                        <p><strong>Suspicious Keywords:</strong> ${data.features.suspicious_keywords}</p>
                        <p><strong>URL Count:</strong> ${data.features.url_count}</p>
                        <p><strong>Suspicious URLs:</strong> ${data.features.suspicious_urls}</p>
                    </div>
                    <div class="col-md-6">
                        <p><strong>Urgency Score:</strong> ${data.features.urgency_score}</p>
                        <p><strong>Email Count:</strong> ${data.features.email_count}</p>
                        <p><strong>All Caps Ratio:</strong> ${(data.features.all_caps_ratio * 100).toFixed(1)}%</p>
                    </div>
                </div>
            </div>
        `;
    }
    
    result.innerHTML = `
        <div class="result-card">
            <h5><i class="fas fa-envelope"></i> Email Analysis Result</h5>
            <div class="row">
                <div class="col-md-6">
                    <p><strong>Threat Type:</strong> ${data.threat_type}</p>
                    <p><strong>Risk Score:</strong> ${data.risk_score}/100</p>
                    <p><strong>Severity:</strong> <span class="severity-badge ${severityClass}">${data.severity}</span></p>
                </div>
                <div class="col-md-6">
                    <p><strong>Phishing Detected:</strong> ${data.is_phishing ? 'Yes' : 'No'}</p>
                    <p><strong>Confidence:</strong> ${(data.confidence * 100).toFixed(1)}%</p>
                </div>
            </div>
            ${featuresHtml}
        </div>
    `;
}

// Display selected files
function displaySelectedFiles() {
    const fileInput = document.getElementById('fileUpload');
    const displayDiv = document.getElementById('selectedFiles');
    const files = fileInput.files;
    
    if (files.length === 0) {
        displayDiv.innerHTML = '';
        return;
    }
    
    let html = '<div class="alert alert-info"><strong>Selected Files:</strong><ul>';
    for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const size = (file.size / 1024).toFixed(1);
        html += `<li>${file.name} (${size} KB)</li>`;
    }
    html += '</ul></div>';
    
    displayDiv.innerHTML = html;
}

// Handle file analysis
async function handleFileAnalysis(event) {
    event.preventDefault();
    
    const loading = document.getElementById('fileLoading');
    const result = document.getElementById('fileResult');
    const fileInput = document.getElementById('fileUpload');
    
    // Show loading
    loading.style.display = 'block';
    result.innerHTML = '';
    
    try {
        const files = fileInput.files;
        if (files.length === 0) {
            throw new Error('Please select at least one file to analyze');
        }
        
        // Create FormData for file upload
        const formData = new FormData();
        formData.append('user_id', document.getElementById('fileUserId').value);
        
        // Add all selected files
        for (let i = 0; i < files.length; i++) {
            formData.append('files', files[i]);
        }
        
        const response = await fetch('/api/analyze_files', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.error) {
            throw new Error(data.error);
        }
        
        // Display result
        displayFileResult(data);
        
        // Refresh dashboard data
        setTimeout(loadDashboardData, 1000);
        
    } catch (error) {
        result.innerHTML = `
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-triangle"></i> Error: ${error.message}
            </div>
        `;
    } finally {
        loading.style.display = 'none';
    }
}

// Display file analysis result
function displayFileResult(data) {
    const result = document.getElementById('fileResult');
    const overallSeverityClass = `severity-${data.overall_analysis.severity.toLowerCase()}`;
    
    let filesHtml = '';
    if (data.file_results && data.file_results.length > 0) {
        filesHtml = '<div class="mt-4"><h6>Individual File Results:</h6>';
        
        data.file_results.forEach(file => {
            if (file.status === 'complete') {
                const fileSeverityClass = `severity-${file.severity.toLowerCase()}`;
                const fileSize = (file.file_size / 1024).toFixed(1);
                
                filesHtml += `
                    <div class="result-card mb-3">
                        <div class="row">
                            <div class="col-md-6">
                                <p><strong>Filename:</strong> ${file.filename}</p>
                                <p><strong>Size:</strong> ${fileSize} KB</p>
                                <p><strong>Type:</strong> ${file.file_extension}</p>
                            </div>
                            <div class="col-md-6">
                                <p><strong>Threat Type:</strong> ${file.threat_type}</p>
                                <p><strong>Risk Score:</strong> ${file.risk_score}/100</p>
                                <p><strong>Severity:</strong> <span class="severity-badge ${fileSeverityClass}">${file.severity}</span></p>
                            </div>
                        </div>
                        ${file.threat_indicators && file.threat_indicators.length > 0 ? `
                            <div class="mt-2">
                                <strong>Threat Indicators Found:</strong>
                                <ul>
                                    ${file.threat_indicators.map(indicator => `<li>${indicator}</li>`).join('')}
                                </ul>
                            </div>
                        ` : ''}
                    </div>
                `;
            } else if (file.status === 'error') {
                filesHtml += `
                    <div class="alert alert-warning">
                        <strong>${file.filename}:</strong> ${file.error}
                    </div>
                `;
            }
        });
        
        filesHtml += '</div>';
    }
    
    result.innerHTML = `
        <div class="result-card">
            <h5><i class="fas fa-file-alt"></i> File Analysis Result</h5>
            <div class="row">
                <div class="col-md-6">
                    <p><strong>Total Files:</strong> ${data.overall_analysis.total_files}</p>
                    <p><strong>Analyzed:</strong> ${data.overall_analysis.analyzed_files}</p>
                    <p><strong>High Risk Files:</strong> ${data.overall_analysis.high_risk_files}</p>
                </div>
                <div class="col-md-6">
                    <p><strong>Overall Risk Score:</strong> ${data.overall_analysis.risk_score}/100</p>
                    <p><strong>Overall Severity:</strong> <span class="severity-badge ${overallSeverityClass}">${data.overall_analysis.severity}</span></p>
                    <p><strong>Medium Risk Files:</strong> ${data.overall_analysis.medium_risk_files}</p>
                </div>
            </div>
            ${filesHtml}
        </div>
    `;
}

// Network Monitoring Variables
let networkRefreshInterval = null;
let trafficTrendChart = null;
let networkThreatChart = null;

function initializeNetworkCharts() {
    // Traffic Trend Chart
    const trafficCtx = document.getElementById('trafficTrendChart');
    if (trafficCtx) {
        trafficTrendChart = new Chart(trafficCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Packets',
                    data: [],
                    borderColor: 'rgb(54, 162, 235)',
                    backgroundColor: 'rgba(54, 162, 235, 0.2)',
                    tension: 0.4,
                    fill: true
                }, {
                    label: 'Threats',
                    data: [],
                    borderColor: 'rgb(255, 99, 132)',
                    backgroundColor: 'rgba(255, 99, 132, 0.2)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: false,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }
    
    // Network Threat Chart
    const threatCtx = document.getElementById('networkThreatChart');
    if (threatCtx) {
        networkThreatChart = new Chart(threatCtx, {
            type: 'pie',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF'
                    ]
                }]
            },
            options: {
                responsive: false,
                maintainAspectRatio: false
            }
        });
    }
}

async function startNetworkMonitoring() {
    try {
        const response = await fetch('/api/network_control', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ action: 'start' })
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
            updateNetworkStatus(true);
            
            // Start auto-refresh
            if (!networkRefreshInterval) {
                networkRefreshInterval = setInterval(loadNetworkData, 3000);
            }
            
            // Initial load
            loadNetworkData();
        }
    } catch (error) {
        console.error('Failed to start network monitoring:', error);
    }
}

async function stopNetworkMonitoring() {
    try {
        const response = await fetch('/api/network_control', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ action: 'stop' })
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
            updateNetworkStatus(false);
            
            // Stop auto-refresh
            if (networkRefreshInterval) {
                clearInterval(networkRefreshInterval);
                networkRefreshInterval = null;
            }
        }
    } catch (error) {
        console.error('Failed to stop network monitoring:', error);
    }
}

function updateNetworkStatus(isActive) {
    const statusBadge = document.getElementById('networkStatus');
    const refreshIcon = document.getElementById('refreshIcon');
    
    if (statusBadge) {
        if (isActive) {
            statusBadge.className = 'badge bg-success me-3';
            statusBadge.textContent = 'Monitoring: Active';
        } else {
            statusBadge.className = 'badge bg-secondary me-3';
            statusBadge.textContent = 'Monitoring: Inactive';
        }
    }
    
    if (refreshIcon) {
        refreshIcon.style.display = isActive ? 'inline-block' : 'none';
    }
}

async function loadNetworkData() {
    try {
        const response = await fetch('/api/network_data');
        const data = await response.json();
        
        if (data.status === 'success') {
            updateNetworkDashboard(data.network_stats);
        }
    } catch (error) {
        console.error('Failed to load network data:', error);
    }
}

function updateNetworkDashboard(stats) {
    // Update summary cards
    document.getElementById('totalPackets').textContent = stats.total_packets || 0;
    document.getElementById('networkThreats').textContent = stats.threats_detected || 0;
    document.getElementById('highRiskPackets').textContent = stats.high_risk_packets || 0;
    document.getElementById('bandwidthUsage').textContent = stats.bandwidth_usage || '0 Mbps';
    
    // Update traffic trend chart
    if (trafficTrendChart && stats.traffic_trend) {
        trafficTrendChart.data.labels = stats.traffic_trend.map(t => t.time);
        trafficTrendChart.data.datasets[0].data = stats.traffic_trend.map(t => t.packets);
        trafficTrendChart.data.datasets[1].data = stats.traffic_trend.map(t => t.threats);
        trafficTrendChart.update();
    }
    
    // Update threat type chart
    if (networkThreatChart && stats.threats_by_type) {
        const threatTypes = Object.keys(stats.threats_by_type);
        const threatCounts = Object.values(stats.threats_by_type);
        
        networkThreatChart.data.labels = threatTypes;
        networkThreatChart.data.datasets[0].data = threatCounts;
        networkThreatChart.update();
    }
    
    // Update network table
    updateNetworkTable(stats.recent_packets);
}

function updateNetworkTable(packets) {
    const tbody = document.getElementById('networkTableBody');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    
    if (!packets || packets.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center">No network activity detected</td></tr>';
        return;
    }
    
    packets.slice(-20).reverse().forEach(packet => {
        const row = document.createElement('tr');
        
        const time = new Date(packet.timestamp).toLocaleTimeString();
        const threatBadge = packet.threat_detected ? 
            `<span class="badge bg-danger">${packet.threat_type}</span>` : 
            '<span class="badge bg-success">Normal</span>';
        
        const severityClass = `severity-${packet.severity.toLowerCase()}`;
        
        row.innerHTML = `
            <td>${time}</td>
            <td>${packet.source_ip}</td>
            <td>${packet.dest_ip}</td>
            <td>${packet.protocol}</td>
            <td>${packet.dest_port}</td>
            <td>${threatBadge}</td>
            <td><span class="severity-badge ${severityClass}">${packet.risk_score}</span></td>
        `;
        
        tbody.appendChild(row);
    });
}

// ============================================
// REAL-TIME ALERT SYSTEM
// ============================================

// Alert configuration
let alertConfig = {
    desktop: { enabled: true, highRiskOnly: true },
    sound: { enabled: true, highRiskOnly: true },
    email: { enabled: false },
    telegram: { enabled: false },
    thresholds: { high: 70, medium: 40 }
};

// Sound alert audio context
let audioContext = null;
let alertSound = null;

// Initialize alert system
document.addEventListener('DOMContentLoaded', function() {
    initAlertSystem();
});

function initAlertSystem() {
    // Load saved configuration
    loadAlertConfig();
    
    // Setup event listeners
    setupAlertEventListeners();
    
    // Check notification permission
    checkNotificationPermission();
    
    // Load recent alerts
    loadRecentAlerts();
    
    // Start alert polling
    setInterval(checkForNewAlerts, 5000);
}

function setupAlertEventListeners() {
    // Enable notifications button
    const enableBtn = document.getElementById('enableNotificationsBtn');
    if (enableBtn) {
        enableBtn.addEventListener('click', requestNotificationPermission);
    }
    
    // Test sound button
    const testSoundBtn = document.getElementById('testSoundBtn');
    if (testSoundBtn) {
        testSoundBtn.addEventListener('click', playAlertSound);
    }
    
    // Test email button
    const testEmailBtn = document.getElementById('testEmailBtn');
    if (testEmailBtn) {
        testEmailBtn.addEventListener('click', () => testAlert('email'));
    }
    
    // Test telegram button
    const testTelegramBtn = document.getElementById('testTelegramBtn');
    if (testTelegramBtn) {
        testTelegramBtn.addEventListener('click', () => testAlert('telegram'));
    }
    
    // Save settings button
    const saveBtn = document.getElementById('saveAlertSettingsBtn');
    if (saveBtn) {
        saveBtn.addEventListener('click', saveAlertSettings);
    }
    
    // Threshold sliders
    const highRiskSlider = document.getElementById('highRiskThreshold');
    if (highRiskSlider) {
        highRiskSlider.addEventListener('input', (e) => {
            document.getElementById('highRiskThresholdValue').textContent = e.target.value;
        });
    }
    
    const mediumRiskSlider = document.getElementById('mediumRiskThreshold');
    if (mediumRiskSlider) {
        mediumRiskSlider.addEventListener('input', (e) => {
            document.getElementById('mediumRiskThresholdValue').textContent = e.target.value;
        });
    }
}

function checkNotificationPermission() {
    if (!('Notification' in window)) {
        updateNotificationStatus('Notifications not supported');
        return;
    }
    
    if (Notification.permission === 'granted') {
        updateNotificationStatus('Enabled');
        document.getElementById('enableNotificationsBtn').style.display = 'none';
    } else if (Notification.permission === 'denied') {
        updateNotificationStatus('Blocked by browser');
    }
}

function requestNotificationPermission() {
    if (!('Notification' in window)) {
        alert('This browser does not support desktop notifications');
        return;
    }
    
    Notification.requestPermission().then(permission => {
        if (permission === 'granted') {
            updateNotificationStatus('Enabled');
            document.getElementById('enableNotificationsBtn').style.display = 'none';
            
            // Show test notification
            new Notification('🛡️ Cybersecurity Dashboard', {
                body: 'Desktop notifications are now enabled!',
                icon: '/static/favicon.ico'
            });
        } else {
            updateNotificationStatus('Permission denied');
        }
    });
}

function updateNotificationStatus(status) {
    const statusEl = document.getElementById('notificationStatus');
    if (statusEl) {
        statusEl.textContent = status;
    }
}

function playAlertSound() {
    try {
        // Create audio context if not exists
        if (!audioContext) {
            audioContext = new (window.AudioContext || window.webkitAudioContext)();
        }
        
        // Create oscillator for alert sound
        const oscillator = audioContext.createOscillator();
        const gainNode = audioContext.createGain();
        
        oscillator.connect(gainNode);
        gainNode.connect(audioContext.destination);
        
        // Alert sound pattern (beep-beep)
        oscillator.frequency.setValueAtTime(800, audioContext.currentTime);
        oscillator.frequency.setValueAtTime(600, audioContext.currentTime + 0.1);
        oscillator.frequency.setValueAtTime(800, audioContext.currentTime + 0.2);
        
        gainNode.gain.setValueAtTime(0.3, audioContext.currentTime);
        gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.5);
        
        oscillator.start(audioContext.currentTime);
        oscillator.stop(audioContext.currentTime + 0.5);
        
    } catch (e) {
        console.error('Failed to play alert sound:', e);
    }
}

async function testAlert(channel) {
    try {
        const response = await fetch('/api/alerts/test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ channel: channel })
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
            showMessage(`alertSettingsMessage`, `Test ${channel} alert sent!`, 'success');
        } else {
            showMessage(`alertSettingsMessage`, `Failed: ${data.error}`, 'danger');
        }
    } catch (error) {
        showMessage(`alertSettingsMessage`, `Error: ${error.message}`, 'danger');
    }
}

function loadAlertConfig() {
    // Load from localStorage
    const saved = localStorage.getItem('alertConfig');
    if (saved) {
        alertConfig = JSON.parse(saved);
        
        // Update UI
        document.getElementById('desktopEnabled').checked = alertConfig.desktop.enabled;
        document.getElementById('desktopHighRiskOnly').checked = alertConfig.desktop.highRiskOnly;
        document.getElementById('soundEnabled').checked = alertConfig.sound.enabled;
        document.getElementById('soundHighRiskOnly').checked = alertConfig.sound.highRiskOnly;
        document.getElementById('emailEnabled').checked = alertConfig.email.enabled;
        document.getElementById('telegramEnabled').checked = alertConfig.telegram.enabled;
        document.getElementById('highRiskThreshold').value = alertConfig.thresholds.high;
        document.getElementById('highRiskThresholdValue').textContent = alertConfig.thresholds.high;
        document.getElementById('mediumRiskThreshold').value = alertConfig.thresholds.medium;
        document.getElementById('mediumRiskThresholdValue').textContent = alertConfig.thresholds.medium;
    }
}

function saveAlertSettings() {
    // Get values from UI
    alertConfig = {
        desktop: {
            enabled: document.getElementById('desktopEnabled').checked,
            highRiskOnly: document.getElementById('desktopHighRiskOnly').checked
        },
        sound: {
            enabled: document.getElementById('soundEnabled').checked,
            highRiskOnly: document.getElementById('soundHighRiskOnly').checked
        },
        email: {
            enabled: document.getElementById('emailEnabled').checked,
            smtpServer: document.getElementById('smtpServer').value,
            username: document.getElementById('emailUsername').value,
            password: document.getElementById('emailPassword').value
        },
        telegram: {
            enabled: document.getElementById('telegramEnabled').checked,
            botToken: document.getElementById('telegramBotToken').value,
            chatIds: document.getElementById('telegramChatIds').value
        },
        thresholds: {
            high: parseInt(document.getElementById('highRiskThreshold').value),
            medium: parseInt(document.getElementById('mediumRiskThreshold').value)
        }
    };
    
    // Save to localStorage
    localStorage.setItem('alertConfig', JSON.stringify(alertConfig));
    
    showMessage('alertSettingsMessage', 'Alert settings saved successfully!', 'success');
}

function showMessage(elementId, message, type) {
    const el = document.getElementById(elementId);
    if (el) {
        el.innerHTML = `<div class="alert alert-${type}">${message}</div>`;
        setTimeout(() => {
            el.innerHTML = '';
        }, 5000);
    }
}

async function loadRecentAlerts() {
    try {
        const response = await fetch('/api/alerts/recent');
        const data = await response.json();
        
        if (data.status === 'success') {
            updateAlertsTable(data.alerts);
        }
    } catch (error) {
        console.error('Failed to load alerts:', error);
    }
}

function updateAlertsTable(alerts) {
    const tbody = document.getElementById('recentAlertsTableBody');
    if (!tbody) return;
    
    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center">No recent alerts</td></tr>';
        return;
    }
    
    tbody.innerHTML = '';
    
    alerts.forEach(alert => {
        const row = document.createElement('tr');
        
        const time = new Date(alert.timestamp).toLocaleTimeString();
        const severityClass = `severity-${alert.severity.toLowerCase()}`;
        const channels = alert.channels ? alert.channels.join(', ') : 'desktop';
        
        row.innerHTML = `
            <td>${time}</td>
            <td>${alert.title}</td>
            <td><span class="severity-badge ${severityClass}">${alert.severity}</span></td>
            <td>${alert.risk_score}</td>
            <td>${channels}</td>
        `;
        
        tbody.appendChild(row);
    });
}

let lastAlertCount = 0;

async function checkForNewAlerts() {
    try {
        const response = await fetch('/api/alerts/recent');
        const data = await response.json();
        
        if (data.status === 'success' && data.alerts) {
            // Check for new alerts
            if (data.alerts.length > lastAlertCount) {
                const newAlerts = data.alerts.slice(0, data.alerts.length - lastAlertCount);
                
                newAlerts.forEach(alert => {
                    triggerDesktopAlert(alert);
                    triggerSoundAlert(alert);
                });
                
                lastAlertCount = data.alerts.length;
            }
            
            // Update table
            updateAlertsTable(data.alerts);
        }
    } catch (error) {
        console.error('Failed to check for alerts:', error);
    }
}

function triggerDesktopAlert(alert) {
    if (!alertConfig.desktop.enabled) return;
    if (alertConfig.desktop.highRiskOnly && alert.risk_score < 70) return;
    
    if (Notification.permission === 'granted') {
        new Notification(alert.title, {
            body: `Risk Score: ${alert.risk_score}/100 - ${alert.severity} severity threat detected`,
            icon: '/static/favicon.ico',
            tag: alert.timestamp,
            requireInteraction: alert.severity === 'High'
        });
    }
}

function triggerSoundAlert(alert) {
    if (!alertConfig.sound.enabled) return;
    if (alertConfig.sound.highRiskOnly && alert.risk_score < 70) return;
    
    playAlertSound();
}
