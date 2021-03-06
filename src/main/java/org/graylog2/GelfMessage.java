package org.graylog2;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.zip.GZIPOutputStream;

public class GelfMessage {

    private static final String ID_NAME = "id";
    private static final String GELF_VERSION = "1.0";
    private static final byte[] GELF_CHUNKED_ID = new byte[]{0x1e, 0x0f};
    private static final int GELF_CHUNK_HEADER_LENGTH = GELF_CHUNKED_ID.length+8+2; // magic + 8 byte message id + 2 byte message number and index
    
    private static final AtomicLong idGen = new AtomicLong();
    private static final byte[] host4bytes ;
    
    static {
        try {
            host4bytes = last4bytes( InetAddress.getLocalHost().getAddress() );
        } catch (UnknownHostException e) {
            throw new IllegalStateException("No localhost found");
        }
    }

    private String version = GELF_VERSION;
    private String host;
    private String shortMessage;
    private String fullMessage;
    private Long timestamp;
    private long javaTimestamp;
    private String level;
    private String facility = "gelf-java";
    private String line;
    private String file;
    private Map<String, Object> additonalFields = new HashMap<String, Object>();

    public GelfMessage() {
    }

    // todo: merge these constructors.

    /**
     * @param address
     * @return
     */
    private static byte[] last4bytes(byte[] address)
    {
        if (address.length>4) {
            // IPv6. getting last 4 bytes of address
            return Arrays.copyOfRange(address, address.length-4, address.length);
        }
        if (address.length!=4) {
            throw new IllegalStateException("Can understand inly IPv4 or IPv6 addresses");
        }
        return address;
    }

    public GelfMessage(String shortMessage, String fullMessage, Date timestamp, String level) {
        this.shortMessage = shortMessage;
        this.fullMessage = fullMessage;
        this.javaTimestamp = timestamp.getTime();
        this.timestamp = javaTimestamp / 1000L;
        this.level = level;
    }

    public GelfMessage(String shortMessage, String fullMessage, Long timestamp, String level, String line, String file) {
        this.shortMessage = shortMessage;
        this.fullMessage = fullMessage;
        this.javaTimestamp = timestamp;
        this.timestamp = javaTimestamp / 1000L;
        this.level = level;
        this.line = line;
        this.file = file;
    }
    
    private void json(Appendable sb, String key, String value, boolean quote) throws IOException
    {
        if (value == null)
            return;
        
        sb.append('"').append(key).append('"').append(':');
        
        if (quote) {
            sb.append('"');
            escape(value,sb);
            sb.append('"').append(',');
        } else {
            sb.append(value).append(',');
        }
    }
    
    private void escape(String s, Appendable sb) throws IOException {
        for(int i=0;i<s.length();i++){
            char ch=s.charAt(i);
            switch(ch){
            case '"':
                sb.append("\\\"");
                break;
            case '\\':
                sb.append("\\\\");
                break;
            case '\b':
                sb.append("\\b");
                break;
            case '\f':
                sb.append("\\f");
                break;
            case '\n':
                sb.append("\\n");
                break;
            case '\r':
                sb.append("\\r");
                break;
            case '\t':
                sb.append("\\t");
                break;
            case '/':
                sb.append("\\/");
                break;
            default:
                //Reference: http://www.unicode.org/versions/Unicode5.1.0/
                if((ch>='\u0000' && ch<='\u001F') || (ch>='\u007F' && ch<='\u009F') || (ch>='\u2000' && ch<='\u20FF')){
                    String ss=Integer.toHexString(ch);
                    sb.append("\\u");
                    for(int k=0;k<4-ss.length();k++){
                        sb.append('0');
                    }
                    sb.append(ss.toUpperCase());
                }
                else{
                    sb.append(ch);
                }
            }
        }//for
    }

    public byte[] toGzipMessage() {
        
        ByteArrayOutputStream bos = new ByteArrayOutputStream(64);

        try {
            GZIPOutputStream stream = new GZIPOutputStream(bos);
            OutputStreamWriter json = new OutputStreamWriter(stream);
        
            write(json);
            
            json.close();
        } catch (IOException e) {
            return null;
        }

        return bos.toByteArray();
    }

    public String toJson() {
        
        StringBuilder json = new StringBuilder(64);

        try {
            write(json);
        } catch (IOException e) {
            return null;
        }
            
        return json.toString();
    }

    /**
     * writes json of message directly to gzip or string buffer without intermediate transformations
     * 
     * @param json
     * @throws IOException
     */
    private void write(Appendable json) throws IOException
    {
        json.append('{');

        json(json,"version", getVersion(),true);
        json(json,"host", getHost(),true);
        json(json,"short_message", getShortMessage(),true);
        json(json,"full_message", getFullMessage(),true);
        json(json,"timestamp", Long.toString( getTimestamp().longValue() ),false);

        json(json,"level", getLevel(),true);
        json(json,"facility", getFacility(),true);
        if( null != getFile() )
        {
            json(json,"file", getFile(),true);
        }
        if( null != getLine() )
        {
            json(json,"line", getLine(),true);
        }
        

        for (Map.Entry<String, Object> additionalField : additonalFields.entrySet()) {
            if (!ID_NAME.equals(additionalField.getKey())) {
                Object value = additionalField.getValue();
                String vstr = value.toString();
                json(json,"_" + additionalField.getKey(), vstr,value==vstr); // String.toString return this, otherwise there will be another instance
            }
        }

        json.append('}');
    }

    public List<byte[]> toDatagrams(int maxChunkSize) {
        byte[] messageBytes = toGzipMessage();
        List<byte[]> datagrams = new ArrayList<byte[]>(messageBytes.length/maxChunkSize+1);
        if (messageBytes.length > maxChunkSize) {
            sliceDatagrams(messageBytes, datagrams, maxChunkSize);
        } else {
            datagrams.add(messageBytes);
        }
        return datagrams;
    }

    private void sliceDatagrams(byte[] messageBytes, List<byte[]> datagrams, int maxChunkSize) {
        final int messageLength = messageBytes.length;
        final int timeMillis = (int) idGen.incrementAndGet() & 0x7FFFFFFF;

        int num = ((Double) Math.ceil((double) messageLength / maxChunkSize)).intValue();
        for (int idx = 0; idx < num; idx++) {
            int from = idx * maxChunkSize;
            int length = Math.min( maxChunkSize, messageLength - from);

            ByteBuffer chunk=ByteBuffer.allocate(GELF_CHUNK_HEADER_LENGTH + length);
            // write header
            chunk.put(GELF_CHUNKED_ID).putInt(timeMillis).put(host4bytes).put((byte)idx).put((byte) num);
            // write body
            chunk.put(messageBytes,from,length);
            datagrams.add(chunk.array());
        }
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public String getShortMessage() {
        return shortMessage;
    }

    public void setShortMessage(String shortMessage) {
        this.shortMessage = shortMessage;
    }

    public String getFullMessage() {
        return fullMessage;
    }

    public void setFullMessage(String fullMessage) {
        this.fullMessage = fullMessage;
    }

    public Long getTimestamp() {
        return timestamp;
    }

    public Long getJavaTimestamp() {
        return javaTimestamp;
    }

    public void setTimestamp(Long timestamp) {
        this.timestamp = timestamp;
    }

    public String getLevel() {
        return level;
    }

    public void setLevel(String level) {
        this.level = level;
    }

    public String getFacility() {
        return facility;
    }

    public void setFacility(String facility) {
        this.facility = facility;
    }

    public String getLine() {
        return line;
    }

    public void setLine(String line) {
        this.line = line;
    }

    public String getFile() {
        return file;
    }

    public void setFile(String file) {
        this.file = file;
    }

    public GelfMessage addField(String key, String value) {
        getAdditonalFields().put(key, value);
        return this;
    }

    public GelfMessage addField(String key, Object value) {
        getAdditonalFields().put(key, value);
        return this;
    }

    public Map<String, Object> getAdditonalFields() {
        return additonalFields;
    }

    public void setAdditonalFields(Map<String, Object> additonalFields) {
        this.additonalFields = additonalFields;
    }

    public boolean isValid() {
        return !isEmpty(version) && !isEmpty(host) && !isEmpty(shortMessage) && !isEmpty(facility);
    }

    public boolean isEmpty(String str) {
        return str == null || "".equals(str.trim());
    }

}
