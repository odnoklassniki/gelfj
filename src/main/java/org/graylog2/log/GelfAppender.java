package org.graylog2.log;

import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.log4j.AppenderSkeleton;
import org.apache.log4j.Category;
import org.apache.log4j.Priority;
import org.apache.log4j.helpers.LogLog;
import org.apache.log4j.spi.ErrorCode;
import org.apache.log4j.spi.LoggingEvent;
import org.graylog2.GelfMessage;
import org.graylog2.GelfMessageFactory;
import org.graylog2.GelfMessageProvider;
import org.graylog2.GelfSender;
import org.json.simple.JSONValue;

/**
 *
 * @author Anton Yakimov
 * @author Jochen Schalanda
 */
public class GelfAppender extends AppenderSkeleton implements GelfMessageProvider {

    private String graylogHost;
    private String originHost = getLocalHostName();
    private int graylogPort = 12201;
    private int maxChunkSize = GelfSender.DEFAULT_CHUNK_SIZE;
    private String facility;
    private GelfSender gelfSender;
    private boolean extractStacktrace;
    private boolean addExtendedInformation;
    private Map<String, String> fields;

    private int messageRateLimit = 0;
    private int messageRateRelaxPeriod = 300; // first 300 seconds we allow to write with full speed
    
    
    private int counter = 0;
    private int droppedmessagecounter = 0;
    private long second ;
    private long servicestarttime ;
    
    public GelfAppender() {
        super();
    }

    public void setAdditionalFields(String additionalFields) {
        fields = (Map<String, String>) JSONValue.parse(additionalFields.replaceAll("'", "\""));
    }

    public int getGraylogPort() {
        return graylogPort;
    }

    public void setGraylogPort(int graylogPort) {
        this.graylogPort = graylogPort;
    }

    public String getGraylogHost() {
        return graylogHost;
    }

    public void setGraylogHost(String graylogHost) {
        this.graylogHost = graylogHost;
    }

    /**
     * { 'regexp_for_host_matching' = 'graylog server', ... }
     */
    public void setGraylogHostMap(String graylogHostMap) {
        Map<String, String> map = (Map<String, String>) JSONValue.parse(graylogHostMap.replaceAll("'", "\""));

        for (Entry<String, String> serverdef : map.entrySet()) {
            if ( getLocalHostName().matches(serverdef.getKey()) ) {
                this.graylogHost = serverdef.getValue();
                return;
            }
        }

        LogLog.error("GELF Cannot determine its server. Host name "+getLocalHostName()+" did not matched anything from map "+graylogHostMap);
    }

    public String getFacility() {
        return facility;
    }

    public void setFacility(String facility) {
        this.facility = facility;
    }

    public boolean isExtractStacktrace() {
        return extractStacktrace;
    }

    public void setExtractStacktrace(boolean extractStacktrace) {
        this.extractStacktrace = extractStacktrace;
    }

    public String getOriginHost() {
        return originHost;
    }

    private  String getLocalHostName() {
        String hostName = null;
        try {
            hostName = InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException e) {
            errorHandler.error("Unknown local hostname", e, ErrorCode.GENERIC_FAILURE);
        }

        return hostName;
    }

    public void setOriginHost(String originHost) {
        this.originHost = originHost;
    }

    public boolean isAddExtendedInformation() {
        return addExtendedInformation;
    }

    public void setAddExtendedInformation(boolean addExtendedInformation) {
        this.addExtendedInformation = addExtendedInformation;
    }
    
    public Map<String, String> getFields() {
        if (fields == null) {
            fields = new HashMap<String, String>();
        }
        return Collections.unmodifiableMap(fields);
    }

    @Override
    public void activateOptions() {
        try {
            gelfSender = new GelfSender(graylogHost, graylogPort, maxChunkSize);
        } catch (UnknownHostException e) {
            errorHandler.error("Unknown Graylog2 hostname:" + getGraylogHost(), e, ErrorCode.WRITE_FAILURE);
        } catch (SocketException e) {
            errorHandler.error("Socket exception", e, ErrorCode.WRITE_FAILURE);
        }
        
        second = System.currentTimeMillis()/1000;
        servicestarttime =  second;

    }

    @Override
    protected void append(LoggingEvent event) {
        
        if (!inMessageLimit())
            return;
        
        appendNoLimit(event);
    }

    private void appendNoLimit(LoggingEvent event)
    {
        GelfMessage gelfMessage = GelfMessageFactory.makeMessage(event, this);

        if(getGelfSender() == null || !getGelfSender().sendMessage(gelfMessage)) {
            errorHandler.error("Could not send GELF message");
        }
    }

    /**
     * @return true, if message limit deactivated or is met
     */
    private boolean inMessageLimit()
    {
        if (messageRateLimit <= 0)
            return true;
        
        long nowSec = System.currentTimeMillis() / 1000;

        if ( servicestarttime + messageRateRelaxPeriod >= nowSec ) 
            return true;
        
        if (second < nowSec ) {
            if (droppedmessagecounter > 0 ) {
                LoggingEvent le = new LoggingEvent( getClass().getName(), Category.getInstance(getClass()), Priority.WARN, "Dropped "+droppedmessagecounter+" messages last second, because limited to "+messageRateLimit+" messages per second", null);
                appendNoLimit(le);
                
                droppedmessagecounter = 0;
            }
            counter = 0;
            second = nowSec;
            
        } else {
            if ( counter++ > messageRateLimit) {
                droppedmessagecounter++;
                return false;
            }
        }
        return true;
    }

    public void setMessageRateLimit(int messageRateLimit)
    {
        this.messageRateLimit = messageRateLimit;
    }
    
    /**
     * @param maxChunkSize the maxChunkSize to set
     */
    public void setMaxChunkSize(int maxChunkSize)
    {
        this.maxChunkSize = maxChunkSize;
    }

    public GelfSender getGelfSender() {
        return gelfSender;
    }

    public void close() {
        getGelfSender().close();
    }

    public boolean requiresLayout() {
        return false;
    }
}
