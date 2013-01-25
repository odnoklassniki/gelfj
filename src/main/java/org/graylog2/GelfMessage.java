package org.graylog2;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPOutputStream;

public class GelfMessage {

    private static final String ID_NAME = "id";
    private static final String GELF_VERSION = "1.0";
    private static final byte[] GELF_CHUNKED_ID = new byte[]{0x1e, 0x0f};

    private String version = GELF_VERSION;
    private String host;
    private byte[] hostBytes = lastFourAsciiBytes("none");
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
        List<byte[]> datagrams = new ArrayList<byte[]>();
        if (messageBytes.length > maxChunkSize) {
            sliceDatagrams(messageBytes, datagrams, maxChunkSize);
        } else {
            datagrams.add(messageBytes);
        }
        return datagrams;
    }

    private void sliceDatagrams(byte[] messageBytes, List<byte[]> datagrams, int maxChunkSize) {
        int messageLength = messageBytes.length;
        byte[] messageId = ByteBuffer.allocate(8)
            .putInt((int) System.currentTimeMillis())       // 4 least-significant-bytes of the time in millis
            .put(hostBytes)                                // 4 least-significant-bytes of the host
            .array();

        int num = ((Double) Math.ceil((double) messageLength / maxChunkSize)).intValue();
        for (int idx = 0; idx < num; idx++) {
            byte[] header = concatByteArray(GELF_CHUNKED_ID, concatByteArray(messageId, new byte[]{(byte) idx, (byte) num}));
            int from = idx * maxChunkSize;
            int to = from + maxChunkSize;
            if (to >= messageLength) {
                to = messageLength;
            }
            byte[] datagram = concatByteArray(header, messageBytes, from, to);
            datagrams.add(datagram);
        }
    }

    private byte[] lastFourAsciiBytes(String host) {
        final String shortHost = host.length() >= 4 ? host.substring(host.length() - 4) : host;
        try {
            return shortHost.getBytes("ASCII");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("JVM without ascii support?", e);
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
        this.hostBytes = lastFourAsciiBytes(host);
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

    private byte[] concatByteArray(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }
    
    private byte[] concatByteArray(byte[] first, byte[] second, int from, int to) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, from, result, first.length, to-from);
        return result;
    }
}
