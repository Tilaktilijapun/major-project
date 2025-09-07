<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:output method="text" indent="no"/>
    
    <xsl:template match="/">{
  "threatDetectionSystem": {
    "metadata": {
      "version": "<xsl:value-of select="threatDetectionSystem/metadata/version"/>",
      "lastUpdated": "<xsl:value-of select="threatDetectionSystem/metadata/lastUpdated"/>",
      "systemStatus": "<xsl:value-of select="threatDetectionSystem/metadata/systemStatus"/>",
      "totalThreats": <xsl:value-of select="threatDetectionSystem/metadata/totalThreats"/>
    },
    "threatCategories": [<xsl:for-each select="threatDetectionSystem/threatCategories/category">
      {
        "id": "<xsl:value-of select="@id"/>",
        "severity": "<xsl:value-of select="@severity"/>",
        "color": "<xsl:value-of select="@color"/>",
        "name": "<xsl:value-of select="name"/>",
        "description": "<xsl:value-of select="description"/>",
        "detectionMethods": [<xsl:for-each select="detectionMethods/method">
          "<xsl:value-of select="."/>"<xsl:if test="position() != last()">,</xsl:if></xsl:for-each>
        ]
      }<xsl:if test="position() != last()">,</xsl:if></xsl:for-each>
    ],
    "activeThreats": [<xsl:for-each select="threatDetectionSystem/activeThreats/threat">
      {
        "id": "<xsl:value-of select="@id"/>",
        "category": "<xsl:value-of select="@category"/>",
        "severity": "<xsl:value-of select="@severity"/>",
        "status": "<xsl:value-of select="@status"/>",
        "timestamp": "<xsl:value-of select="timestamp"/>",
        "title": "<xsl:value-of select="title"/>",
        "description": "<xsl:value-of select="description"/>",
        "impact": "<xsl:value-of select="impact"/>",
        "recommendedAction": "<xsl:value-of select="recommendedAction"/>",
        "source": {<xsl:choose>
          <xsl:when test="source/ip">
            "ip": "<xsl:value-of select="source/ip"/>",
            "location": "<xsl:value-of select="source/location"/>",
            "userAgent": "<xsl:value-of select="source/userAgent"/>"</xsl:when>
          <xsl:when test="source/file">
            "file": "<xsl:value-of select="source/file"/>",
            "hash": "<xsl:value-of select="source/hash"/>",
            "size": <xsl:value-of select="source/size"/></xsl:when>
          <xsl:when test="source/email">
            "email": "<xsl:value-of select="source/email"/>",
            "subject": "<xsl:value-of select="source/subject"/>",
            "recipient": "<xsl:value-of select="source/recipient"/>"</xsl:when>
          <xsl:when test="source/targetPort">
            "targetPort": <xsl:value-of select="source/targetPort"/>,
            "requestVolume": <xsl:value-of select="source/requestVolume"/>,
            "sourceIPs": <xsl:value-of select="source/sourceIPs"/></xsl:when>
          <xsl:when test="source/port">
            "port": <xsl:value-of select="source/port"/>,
            "protocol": "<xsl:value-of select="source/protocol"/>",
            "dataVolume": "<xsl:value-of select="source/dataVolume"/>"</xsl:when>
        </xsl:choose>
        },
        "affectedSystems": [<xsl:for-each select="affectedSystems/system">
          "<xsl:value-of select="."/>"<xsl:if test="position() != last()">,</xsl:if></xsl:for-each>
        ]
      }<xsl:if test="position() != last()">,</xsl:if></xsl:for-each>
    ],
    "statistics": {
      "dailyStats": {
        "date": "<xsl:value-of select="threatDetectionSystem/statistics/dailyStats/@date"/>",
        "threatsDetected": <xsl:value-of select="threatDetectionSystem/statistics/dailyStats/threatsDetected"/>,
        "threatsBlocked": <xsl:value-of select="threatDetectionSystem/statistics/dailyStats/threatsBlocked"/>,
        "threatsInvestigating": <xsl:value-of select="threatDetectionSystem/statistics/dailyStats/threatsInvestigating"/>,
        "systemUptime": <xsl:value-of select="threatDetectionSystem/statistics/dailyStats/systemUptime"/>
      },
      "weeklyTrends": [<xsl:for-each select="threatDetectionSystem/statistics/weeklyTrends/trend">
        {
          "category": "<xsl:value-of select="@category"/>",
          "change": "<xsl:value-of select="@change"/>",
          "direction": "<xsl:value-of select="@direction"/>"
        }<xsl:if test="position() != last()">,</xsl:if></xsl:for-each>
      ]
    },
    "systemConfiguration": {
      "scanningEnabled": <xsl:value-of select="threatDetectionSystem/systemConfiguration/scanningEnabled"/>,
      "realTimeProtection": <xsl:value-of select="threatDetectionSystem/systemConfiguration/realTimeProtection"/>,
      "automaticUpdates": <xsl:value-of select="threatDetectionSystem/systemConfiguration/automaticUpdates"/>,
      "alertNotifications": <xsl:value-of select="threatDetectionSystem/systemConfiguration/alertNotifications"/>,
      "quarantineEnabled": <xsl:value-of select="threatDetectionSystem/systemConfiguration/quarantineEnabled"/>,
      "logRetentionDays": <xsl:value-of select="threatDetectionSystem/systemConfiguration/logRetentionDays"/>
    }
  }
}
    </xsl:template>
</xsl:stylesheet>