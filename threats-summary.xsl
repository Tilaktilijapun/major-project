<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:output method="html" doctype-public="-//W3C//DTD HTML 4.01//EN" doctype-system="http://www.w3.org/TR/html4/strict.dtd"/>
    
    <xsl:template match="/">
        <html>
            <head>
                <title>AIVivid - Threat Summary Report</title>
                <meta charset="UTF-8"/>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
                    .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                    .header { text-align: center; margin-bottom: 30px; }
                    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
                    .stat-card { background: #f8f9fa; padding: 15px; border-radius: 6px; text-align: center; }
                    .stat-number { font-size: 24px; font-weight: bold; color: #2563eb; }
                    .threat-summary { margin-bottom: 20px; }
                    .severity-high { color: #dc2626; }
                    .severity-medium { color: #d97706; }
                    .severity-low { color: #059669; }
                    .severity-critical { color: #991b1b; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>AIVivid Threat Detection Summary</h1>
                        <p>Generated on: <xsl:value-of select="threatDetectionSystem/metadata/lastUpdated"/></p>
                        <p>System Version: <xsl:value-of select="threatDetectionSystem/metadata/version"/></p>
                    </div>
                    
                    <div class="stats-grid">
                        <div class="stat-card">
                            <div class="stat-number"><xsl:value-of select="threatDetectionSystem/statistics/dailyStats/threatsDetected"/></div>
                            <div>Threats Detected Today</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number"><xsl:value-of select="threatDetectionSystem/statistics/dailyStats/threatsBlocked"/></div>
                            <div>Threats Blocked</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number"><xsl:value-of select="threatDetectionSystem/statistics/dailyStats/threatsInvestigating"/></div>
                            <div>Under Investigation</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number"><xsl:value-of select="threatDetectionSystem/statistics/dailyStats/systemUptime"/>%</div>
                            <div>System Uptime</div>
                        </div>
                    </div>
                    
                    <div class="threat-summary">
                        <h2>Active Threats by Severity</h2>
                        <xsl:variable name="critical" select="count(threatDetectionSystem/activeThreats/threat[@severity='critical'])"/>
                        <xsl:variable name="high" select="count(threatDetectionSystem/activeThreats/threat[@severity='high'])"/>
                        <xsl:variable name="medium" select="count(threatDetectionSystem/activeThreats/threat[@severity='medium'])"/>
                        <xsl:variable name="low" select="count(threatDetectionSystem/activeThreats/threat[@severity='low'])"/>
                        
                        <ul>
                            <li class="severity-critical">Critical: <xsl:value-of select="$critical"/> threats</li>
                            <li class="severity-high">High: <xsl:value-of select="$high"/> threats</li>
                            <li class="severity-medium">Medium: <xsl:value-of select="$medium"/> threats</li>
                            <li class="severity-low">Low: <xsl:value-of select="$low"/> threats</li>
                        </ul>
                    </div>
                    
                    <div class="threat-summary">
                        <h2>Weekly Trends</h2>
                        <ul>
                            <xsl:for-each select="threatDetectionSystem/statistics/weeklyTrends/trend">
                                <li>
                                    <xsl:value-of select="@category"/>: 
                                    <xsl:choose>
                                        <xsl:when test="@direction='up'">↗</xsl:when>
                                        <xsl:otherwise>↘</xsl:otherwise>
                                    </xsl:choose>
                                    <xsl:value-of select="@change"/>
                                </li>
                            </xsl:for-each>
                        </ul>
                    </div>
                    
                    <div class="threat-summary">
                        <h2>System Configuration</h2>
                        <ul>
                            <li>Real-time Protection: <xsl:value-of select="threatDetectionSystem/systemConfiguration/realTimeProtection"/></li>
                            <li>Automatic Updates: <xsl:value-of select="threatDetectionSystem/systemConfiguration/automaticUpdates"/></li>
                            <li>Alert Notifications: <xsl:value-of select="threatDetectionSystem/systemConfiguration/alertNotifications"/></li>
                            <li>Quarantine Enabled: <xsl:value-of select="threatDetectionSystem/systemConfiguration/quarantineEnabled"/></li>
                            <li>Log Retention: <xsl:value-of select="threatDetectionSystem/systemConfiguration/logRetentionDays"/> days</li>
                        </ul>
                    </div>
                </div>
            </body>
        </html>
    </xsl:template>
</xsl:stylesheet>