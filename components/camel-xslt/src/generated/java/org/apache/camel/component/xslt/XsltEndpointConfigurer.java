/* Generated by camel build tools - do NOT edit this file! */
package org.apache.camel.component.xslt;

import javax.annotation.processing.Generated;
import java.util.Map;

import org.apache.camel.CamelContext;
import org.apache.camel.spi.ExtendedPropertyConfigurerGetter;
import org.apache.camel.spi.PropertyConfigurerGetter;
import org.apache.camel.spi.ConfigurerStrategy;
import org.apache.camel.spi.GeneratedPropertyConfigurer;
import org.apache.camel.util.CaseInsensitiveMap;
import org.apache.camel.support.component.PropertyConfigurerSupport;

/**
 * Generated by camel build tools - do NOT edit this file!
 */
@Generated("org.apache.camel.maven.packaging.EndpointSchemaGeneratorMojo")
@SuppressWarnings("unchecked")
public class XsltEndpointConfigurer extends PropertyConfigurerSupport implements GeneratedPropertyConfigurer, PropertyConfigurerGetter {

    @Override
    public boolean configure(CamelContext camelContext, Object obj, String name, Object value, boolean ignoreCase) {
        XsltEndpoint target = (XsltEndpoint) obj;
        switch (ignoreCase ? name.toLowerCase() : name) {
        case "allowtemplatefromheader":
        case "allowTemplateFromHeader": target.setAllowTemplateFromHeader(property(camelContext, boolean.class, value)); return true;
        case "contentcache":
        case "contentCache": target.setContentCache(property(camelContext, boolean.class, value)); return true;
        case "deleteoutputfile":
        case "deleteOutputFile": target.setDeleteOutputFile(property(camelContext, boolean.class, value)); return true;
        case "entityresolver":
        case "entityResolver": target.setEntityResolver(property(camelContext, org.xml.sax.EntityResolver.class, value)); return true;
        case "errorlistener":
        case "errorListener": target.setErrorListener(property(camelContext, javax.xml.transform.ErrorListener.class, value)); return true;
        case "failonnullbody":
        case "failOnNullBody": target.setFailOnNullBody(property(camelContext, boolean.class, value)); return true;
        case "lazystartproducer":
        case "lazyStartProducer": target.setLazyStartProducer(property(camelContext, boolean.class, value)); return true;
        case "output": target.setOutput(property(camelContext, org.apache.camel.component.xslt.XsltOutput.class, value)); return true;
        case "resulthandlerfactory":
        case "resultHandlerFactory": target.setResultHandlerFactory(property(camelContext, org.apache.camel.component.xslt.ResultHandlerFactory.class, value)); return true;
        case "source": target.setSource(property(camelContext, java.lang.String.class, value)); return true;
        case "transformercachesize":
        case "transformerCacheSize": target.setTransformerCacheSize(property(camelContext, int.class, value)); return true;
        case "transformerfactory":
        case "transformerFactory": target.setTransformerFactory(property(camelContext, javax.xml.transform.TransformerFactory.class, value)); return true;
        case "transformerfactoryclass":
        case "transformerFactoryClass": target.setTransformerFactoryClass(property(camelContext, java.lang.String.class, value)); return true;
        case "transformerfactoryconfigurationstrategy":
        case "transformerFactoryConfigurationStrategy": target.setTransformerFactoryConfigurationStrategy(property(camelContext, org.apache.camel.component.xslt.TransformerFactoryConfigurationStrategy.class, value)); return true;
        case "uriresolver":
        case "uriResolver": target.setUriResolver(property(camelContext, javax.xml.transform.URIResolver.class, value)); return true;
        case "xsltmessagelogger":
        case "xsltMessageLogger": target.setXsltMessageLogger(property(camelContext, org.apache.camel.component.xslt.XsltMessageLogger.class, value)); return true;
        default: return false;
        }
    }

    @Override
    public Class<?> getOptionType(String name, boolean ignoreCase) {
        switch (ignoreCase ? name.toLowerCase() : name) {
        case "allowtemplatefromheader":
        case "allowTemplateFromHeader": return boolean.class;
        case "contentcache":
        case "contentCache": return boolean.class;
        case "deleteoutputfile":
        case "deleteOutputFile": return boolean.class;
        case "entityresolver":
        case "entityResolver": return org.xml.sax.EntityResolver.class;
        case "errorlistener":
        case "errorListener": return javax.xml.transform.ErrorListener.class;
        case "failonnullbody":
        case "failOnNullBody": return boolean.class;
        case "lazystartproducer":
        case "lazyStartProducer": return boolean.class;
        case "output": return org.apache.camel.component.xslt.XsltOutput.class;
        case "resulthandlerfactory":
        case "resultHandlerFactory": return org.apache.camel.component.xslt.ResultHandlerFactory.class;
        case "source": return java.lang.String.class;
        case "transformercachesize":
        case "transformerCacheSize": return int.class;
        case "transformerfactory":
        case "transformerFactory": return javax.xml.transform.TransformerFactory.class;
        case "transformerfactoryclass":
        case "transformerFactoryClass": return java.lang.String.class;
        case "transformerfactoryconfigurationstrategy":
        case "transformerFactoryConfigurationStrategy": return org.apache.camel.component.xslt.TransformerFactoryConfigurationStrategy.class;
        case "uriresolver":
        case "uriResolver": return javax.xml.transform.URIResolver.class;
        case "xsltmessagelogger":
        case "xsltMessageLogger": return org.apache.camel.component.xslt.XsltMessageLogger.class;
        default: return null;
        }
    }

    @Override
    public Object getOptionValue(Object obj, String name, boolean ignoreCase) {
        XsltEndpoint target = (XsltEndpoint) obj;
        switch (ignoreCase ? name.toLowerCase() : name) {
        case "allowtemplatefromheader":
        case "allowTemplateFromHeader": return target.isAllowTemplateFromHeader();
        case "contentcache":
        case "contentCache": return target.isContentCache();
        case "deleteoutputfile":
        case "deleteOutputFile": return target.isDeleteOutputFile();
        case "entityresolver":
        case "entityResolver": return target.getEntityResolver();
        case "errorlistener":
        case "errorListener": return target.getErrorListener();
        case "failonnullbody":
        case "failOnNullBody": return target.isFailOnNullBody();
        case "lazystartproducer":
        case "lazyStartProducer": return target.isLazyStartProducer();
        case "output": return target.getOutput();
        case "resulthandlerfactory":
        case "resultHandlerFactory": return target.getResultHandlerFactory();
        case "source": return target.getSource();
        case "transformercachesize":
        case "transformerCacheSize": return target.getTransformerCacheSize();
        case "transformerfactory":
        case "transformerFactory": return target.getTransformerFactory();
        case "transformerfactoryclass":
        case "transformerFactoryClass": return target.getTransformerFactoryClass();
        case "transformerfactoryconfigurationstrategy":
        case "transformerFactoryConfigurationStrategy": return target.getTransformerFactoryConfigurationStrategy();
        case "uriresolver":
        case "uriResolver": return target.getUriResolver();
        case "xsltmessagelogger":
        case "xsltMessageLogger": return target.getXsltMessageLogger();
        default: return null;
        }
    }
}

