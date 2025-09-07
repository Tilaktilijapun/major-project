<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:output method="text" encoding="UTF-8"/>
    
    <xsl:template match="/">
        <xsl:text>ID,Category,Severity,Status,Timestamp,Title,Description,Impact,Recommended Action,Affected Systems&#10;</xsl:text>
        <xsl:for-each select="threatDetectionSystem/activeThreats/threat">
            <xsl:value-of select="@id"/>,
            <xsl:value-of select="@category"/>,
            <xsl:value-of select="@severity"/>,
            <xsl:value-of select="@status"/>,
            <xsl:value-of select="timestamp"/>,
            "<xsl:value-of select="title"/>",
            "<xsl:value-of select="description"/>",
            <xsl:value-of select="impact"/>,
            "<xsl:value-of select="recommendedAction"/>",
            "<xsl:for-each select="affectedSystems/system">
                <xsl:value-of select="."/>
                <xsl:if test="position() != last()">; </xsl:if>
            </xsl:for-each>"<xsl:text>&#10;</xsl:text>
        </xsl:for-each>
    </xsl:template>
</xsl:stylesheet>