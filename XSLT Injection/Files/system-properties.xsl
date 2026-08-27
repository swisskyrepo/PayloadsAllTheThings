<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
<p>
Version: <xsl:value-of select="system-property('xsl:version')" /> <br />
Vendor: <xsl:value-of select="system-property('xsl:vendor')" /> <br />
Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" />
</p>
</xsl:template>
</xsl:stylesheet>