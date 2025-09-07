<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:output method="html" doctype-public="-//W3C//DTD HTML 4.01//EN" doctype-system="http://www.w3.org/TR/html4/strict.dtd"/>
    
    <xsl:template match="/">
        <html>
            <head>
                <title>AIVivid - Threat Detection Dashboard</title>
                <meta charset="UTF-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
                <script src="https://cdn.tailwindcss.com"></script>
                <style>
                    :root {
                        --primary: #3B82F6;
                        --secondary: #1E40AF;
                        --dark: #0F172A;
                        --accent: #a3c614;
                    }
                    
                    .threat-high { border-left-color: #dc2626; }
                    .threat-medium { border-left-color: #d97706; }
                    .threat-low { border-left-color: #059669; }
                    .threat-critical { border-left-color: #991b1b; }
                    
                    .status-active { background-color: #fef2f2; color: #dc2626; }
                    .status-blocked { background-color: #f0fdf4; color: #059669; }
                    .status-investigating { background-color: #fffbeb; color: #d97706; }
                    .status-quarantined { background-color: #f3f4f6; color: #6b7280; }
                    .status-mitigated { background-color: #eff6ff; color: #2563eb; }
                    
                    .animate-pulse-slow {
                        animation: pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite;
                    }
                </style>
            </head>
            <body class="bg-gray-900 text-white min-h-screen">
                <div class="container mx-auto px-4 py-8">
                    <!-- Header -->
                    <div class="mb-8">
                        <h1 class="text-4xl font-bold text-center mb-2">
                            <span class="text-blue-400">AIVivid</span> Threat Detection
                        </h1>
                        <p class="text-gray-400 text-center">
                            System Status: <span class="text-green-400 font-semibold">
                                <xsl:value-of select="threatDetectionSystem/metadata/systemStatus"/>
                            </span> | 
                            Last Updated: <xsl:value-of select="threatDetectionSystem/metadata/lastUpdated"/>
                        </p>
                    </div>
                    
                    <!-- Statistics Overview -->
                    <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
                        <div class="bg-gray-800 p-6 rounded-lg border border-gray-700">
                            <h3 class="text-lg font-semibold text-gray-300 mb-2">Total Threats</h3>
                            <p class="text-3xl font-bold text-blue-400">
                                <xsl:value-of select="threatDetectionSystem/metadata/totalThreats"/>
                            </p>
                        </div>
                        <div class="bg-gray-800 p-6 rounded-lg border border-gray-700">
                            <h3 class="text-lg font-semibold text-gray-300 mb-2">Today's Detections</h3>
                            <p class="text-3xl font-bold text-yellow-400">
                                <xsl:value-of select="threatDetectionSystem/statistics/dailyStats/threatsDetected"/>
                            </p>
                        </div>
                        <div class="bg-gray-800 p-6 rounded-lg border border-gray-700">
                            <h3 class="text-lg font-semibold text-gray-300 mb-2">Blocked</h3>
                            <p class="text-3xl font-bold text-green-400">
                                <xsl:value-of select="threatDetectionSystem/statistics/dailyStats/threatsBlocked"/>
                            </p>
                        </div>
                        <div class="bg-gray-800 p-6 rounded-lg border border-gray-700">
                            <h3 class="text-lg font-semibold text-gray-300 mb-2">System Uptime</h3>
                            <p class="text-3xl font-bold text-blue-400">
                                <xsl:value-of select="threatDetectionSystem/statistics/dailyStats/systemUptime"/>%
                            </p>
                        </div>
                    </div>
                    
                    <!-- Active Threats -->
                    <div class="mb-8">
                        <h2 class="text-2xl font-bold mb-6 text-blue-400">Active Threats</h2>
                        <div class="space-y-4">
                            <xsl:for-each select="threatDetectionSystem/activeThreats/threat">
                                <div class="bg-gray-800 p-6 rounded-lg border-l-4">
                                    <xsl:attribute name="class">
                                        bg-gray-800 p-6 rounded-lg border-l-4
                                        <xsl:choose>
                                            <xsl:when test="@severity='critical'">threat-critical</xsl:when>
                                            <xsl:when test="@severity='high'">threat-high</xsl:when>
                                            <xsl:when test="@severity='medium'">threat-medium</xsl:when>
                                            <xsl:otherwise>threat-low</xsl:otherwise>
                                        </xsl:choose>
                                    </xsl:attribute>
                                    
                                    <div class="flex justify-between items-start mb-4">
                                        <div>
                                            <h3 class="text-xl font-semibold text-white mb-2">
                                                <xsl:value-of select="title"/>
                                            </h3>
                                            <p class="text-gray-300 mb-2">
                                                <xsl:value-of select="description"/>
                                            </p>
                                            <p class="text-sm text-gray-400">
                                                ID: <xsl:value-of select="@id"/> | 
                                                <xsl:value-of select="timestamp"/>
                                            </p>
                                        </div>
                                        <div class="flex flex-col items-end space-y-2">
                                            <span class="px-3 py-1 rounded-full text-xs font-medium">
                                                <xsl:attribute name="class">
                                                    px-3 py-1 rounded-full text-xs font-medium status-<xsl:value-of select="@status"/>
                                                </xsl:attribute>
                                                <xsl:value-of select="@status"/>
                                            </span>
                                            <span class="px-2 py-1 bg-gray-700 text-gray-300 rounded text-xs">
                                                <xsl:value-of select="@severity"/>
                                            </span>
                                        </div>
                                    </div>
                                    
                                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                                        <div>
                                            <h4 class="font-semibold text-gray-300 mb-2">Impact:</h4>
                                            <p class="text-gray-400"><xsl:value-of select="impact"/></p>
                                        </div>
                                        <div>
                                            <h4 class="font-semibold text-gray-300 mb-2">Recommended Action:</h4>
                                            <p class="text-gray-400"><xsl:value-of select="recommendedAction"/></p>
                                        </div>
                                    </div>
                                    
                                    <div class="mt-4">
                                        <h4 class="font-semibold text-gray-300 mb-2">Affected Systems:</h4>
                                        <div class="flex flex-wrap gap-2">
                                            <xsl:for-each select="affectedSystems/system">
                                                <span class="px-2 py-1 bg-blue-900 text-blue-300 rounded text-xs">
                                                    <xsl:value-of select="."/>
                                                </span>
                                            </xsl:for-each>
                                        </div>
                                    </div>
                                </div>
                            </xsl:for-each>
                        </div>
                    </div>
                    
                    <!-- Threat Categories -->
                    <div class="mb-8">
                        <h2 class="text-2xl font-bold mb-6 text-blue-400">Threat Categories</h2>
                        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                            <xsl:for-each select="threatDetectionSystem/threatCategories/category">
                                <div class="bg-gray-800 p-6 rounded-lg border border-gray-700 hover:border-blue-500 transition duration-300">
                                    <h3 class="text-lg font-semibold text-white mb-2">
                                        <xsl:value-of select="name"/>
                                    </h3>
                                    <p class="text-gray-400 text-sm mb-4">
                                        <xsl:value-of select="description"/>
                                    </p>
                                    <div class="mb-4">
                                        <span class="px-2 py-1 rounded text-xs font-medium">
                                            <xsl:attribute name="style">
                                                background-color: <xsl:value-of select="@color"/>20;
                                                color: <xsl:value-of select="@color"/>;
                                            </xsl:attribute>
                                            <xsl:value-of select="@severity"/> severity
                                        </span>
                                    </div>
                                    <div>
                                        <h4 class="text-sm font-semibold text-gray-300 mb-2">Detection Methods:</h4>
                                        <ul class="text-xs text-gray-400 space-y-1">
                                            <xsl:for-each select="detectionMethods/method">
                                                <li>• <xsl:value-of select="."/></li>
                                            </xsl:for-each>
                                        </ul>
                                    </div>
                                </div>
                            </xsl:for-each>
                        </div>
                    </div>
                    
                    <!-- Weekly Trends -->
                    <div class="mb-8">
                        <h2 class="text-2xl font-bold mb-6 text-blue-400">Weekly Trends</h2>
                        <div class="bg-gray-800 p-6 rounded-lg border border-gray-700">
                            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                                <xsl:for-each select="threatDetectionSystem/statistics/weeklyTrends/trend">
                                    <div class="text-center">
                                        <h3 class="text-lg font-semibold text-white capitalize mb-2">
                                            <xsl:value-of select="@category"/>
                                        </h3>
                                        <p class="text-2xl font-bold mb-1">
                                            <xsl:attribute name="class">
                                                text-2xl font-bold mb-1
                                                <xsl:choose>
                                                    <xsl:when test="@direction='up'">text-red-400</xsl:when>
                                                    <xsl:otherwise>text-green-400</xsl:otherwise>
                                                </xsl:choose>
                                            </xsl:attribute>
                                            <xsl:value-of select="@change"/>
                                        </p>
                                        <p class="text-sm text-gray-400">
                                            <xsl:choose>
                                                <xsl:when test="@direction='up'">↗ Increase</xsl:when>
                                                <xsl:otherwise>↘ Decrease</xsl:otherwise>
                                            </xsl:choose>
                                        </p>
                                    </div>
                                </xsl:for-each>
                            </div>
                        </div>
                    </div>
                    
                    <!-- System Configuration -->
                    <div>
                        <h2 class="text-2xl font-bold mb-6 text-blue-400">System Configuration</h2>
                        <div class="bg-gray-800 p-6 rounded-lg border border-gray-700">
                            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                                <div class="flex justify-between items-center">
                                    <span class="text-gray-300">Real-time Protection</span>
                                    <span class="text-green-400 font-semibold">
                                        <xsl:choose>
                                            <xsl:when test="threatDetectionSystem/systemConfiguration/realTimeProtection='true'">Enabled</xsl:when>
                                            <xsl:otherwise>Disabled</xsl:otherwise>
                                        </xsl:choose>
                                    </span>
                                </div>
                                <div class="flex justify-between items-center">
                                    <span class="text-gray-300">Automatic Updates</span>
                                    <span class="text-green-400 font-semibold">
                                        <xsl:choose>
                                            <xsl:when test="threatDetectionSystem/systemConfiguration/automaticUpdates='true'">Enabled</xsl:when>
                                            <xsl:otherwise>Disabled</xsl:otherwise>
                                        </xsl:choose>
                                    </span>
                                </div>
                                <div class="flex justify-between items-center">
                                    <span class="text-gray-300">Alert Notifications</span>
                                    <span class="text-green-400 font-semibold">
                                        <xsl:choose>
                                            <xsl:when test="threatDetectionSystem/systemConfiguration/alertNotifications='true'">Enabled</xsl:when>
                                            <xsl:otherwise>Disabled</xsl:otherwise>
                                        </xsl:choose>
                                    </span>
                                </div>
                                <div class="flex justify-between items-center">
                                    <span class="text-gray-300">Quarantine</span>
                                    <span class="text-green-400 font-semibold">
                                        <xsl:choose>
                                            <xsl:when test="threatDetectionSystem/systemConfiguration/quarantineEnabled='true'">Enabled</xsl:when>
                                            <xsl:otherwise>Disabled</xsl:otherwise>
                                        </xsl:choose>
                                    </span>
                                </div>
                                <div class="flex justify-between items-center">
                                    <span class="text-gray-300">Log Retention</span>
                                    <span class="text-blue-400 font-semibold">
                                        <xsl:value-of select="threatDetectionSystem/systemConfiguration/logRetentionDays"/> days
                                    </span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </body>
        </html>
    </xsl:template>
</xsl:stylesheet>