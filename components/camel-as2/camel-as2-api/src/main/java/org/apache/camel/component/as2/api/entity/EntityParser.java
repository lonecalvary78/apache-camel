/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.camel.component.as2.api.entity;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

import org.apache.camel.CamelException;
import org.apache.camel.component.as2.api.AS2Header;
import org.apache.camel.component.as2.api.AS2MimeType;
import org.apache.camel.component.as2.api.exception.AS2DecryptionException;
import org.apache.camel.component.as2.api.io.AS2SessionInputBuffer;
import org.apache.camel.component.as2.api.util.AS2HeaderUtils;
import org.apache.camel.component.as2.api.util.ContentTypeUtils;
import org.apache.camel.component.as2.api.util.DispositionNotificationContentUtils;
import org.apache.camel.component.as2.api.util.EntityUtils;
import org.apache.camel.component.as2.api.util.HttpMessageUtils;
import org.apache.camel.util.ObjectHelper;
import org.apache.commons.codec.DecoderException;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpMessage;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.impl.BasicHttpTransportMetrics;
import org.apache.hc.core5.http.impl.io.AbstractMessageParser;
import org.apache.hc.core5.http.message.BasicLineParser;
import org.apache.hc.core5.http.message.BasicNameValuePair;
import org.apache.hc.core5.http.message.LineParser;
import org.apache.hc.core5.http.message.ParserCursor;
import org.apache.hc.core5.util.Args;
import org.apache.hc.core5.util.CharArrayBuffer;
import org.bouncycastle.cms.CMSCompressedData;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.Recipient;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.operator.InputExpanderProvider;

public final class EntityParser {

    private static final int CR = 13; // <US-ASCII CR, carriage return (13)>
    private static final int LF = 10; // <US-ASCII LF, linefeed (10)>

    private static final int DEFAULT_BUFFER_SIZE = 8 * 1024;

    private EntityParser() {
    }

    public static boolean isBoundaryCloseDelimiter(final CharArrayBuffer buffer, ParserCursor cursor, String boundary) {
        ObjectHelper.notNull(buffer, "Buffer");
        ObjectHelper.notNull(boundary, "Boundary");

        String boundaryCloseDelimiter = "--" + boundary + "--"; // boundary
        // close-delimiter
        // - RFC2046
        // 5.1.1

        if (cursor == null) {
            cursor = new ParserCursor(0, boundaryCloseDelimiter.length());
        }

        int indexFrom = cursor.getPos();
        int indexTo = cursor.getUpperBound();

        if ((indexFrom + boundaryCloseDelimiter.length()) > indexTo) {
            return false;
        }

        for (int i = indexFrom; i < indexTo; ++i) {
            if (buffer.charAt(i) != boundaryCloseDelimiter.charAt(i)) {
                return false;
            }
        }

        return true;
    }

    public static boolean isBoundaryDelimiter(final CharArrayBuffer buffer, ParserCursor cursor, String boundary) {
        ObjectHelper.notNull(buffer, "Buffer");
        ObjectHelper.notNull(boundary, "Boundary");

        String boundaryDelimiter = "--" + boundary; // boundary delimiter -
        // RFC2046 5.1.1

        if (cursor == null) {
            cursor = new ParserCursor(0, boundaryDelimiter.length());
        }

        int indexFrom = cursor.getPos();
        int indexTo = cursor.getUpperBound();

        if ((indexFrom + boundaryDelimiter.length()) > indexTo) {
            return false;
        }

        for (int i = indexFrom; i < indexTo; ++i) {
            if (buffer.charAt(i) != boundaryDelimiter.charAt(i)) {
                return false;
            }
        }

        return true;
    }

    public static void skipPreambleAndStartBoundary(AS2SessionInputBuffer inbuffer, InputStream is, String boundary)
            throws HttpException {

        boolean foundStartBoundary;
        try {
            foundStartBoundary = false;
            CharArrayBuffer lineBuffer = new CharArrayBuffer(1024);
            while (inbuffer.readLine(lineBuffer, is) != -1) {
                final ParserCursor cursor = new ParserCursor(0, lineBuffer.length());
                if (isBoundaryDelimiter(lineBuffer, cursor, boundary)) {
                    foundStartBoundary = true;
                    break;
                }
                lineBuffer.clear();
            }
        } catch (Exception e) {
            throw new HttpException("Failed to read start boundary for body part", e);
        }

        if (!foundStartBoundary) {
            throw new HttpException("Failed to find start boundary for body part");
        }

    }

    public static void skipToBoundary(AS2SessionInputBuffer inbuffer, InputStream is, String boundary)
            throws HttpException {

        boolean foundEndBoundary;
        try {
            foundEndBoundary = false;
            CharArrayBuffer lineBuffer = new CharArrayBuffer(1024);
            while (inbuffer.readLine(lineBuffer, is) != -1) {
                final ParserCursor cursor = new ParserCursor(0, lineBuffer.length());
                if (isBoundaryDelimiter(lineBuffer, cursor, boundary)) {
                    foundEndBoundary = true;
                    break;
                }
                lineBuffer.clear();
            }
        } catch (Exception e) {
            throw new HttpException("Failed to read start boundary for body part", e);
        }

        if (!foundEndBoundary && boundary != null) {
            throw new HttpException("Failed to find start boundary for body part");
        }

    }

    public static MimeEntity parseCompressedEntity(byte[] compressedData, InputExpanderProvider expanderProvider)
            throws HttpException {

        byte[] uncompressedContent = uncompressData(compressedData, expanderProvider);

        return parseEntity(uncompressedContent);
    }

    public static MimeEntity parseEnvelopedEntity(byte[] envelopedContent, PrivateKey privateKey) throws HttpException {

        byte[] decryptedContent = decryptData(envelopedContent, privateKey);

        return parseEntity(decryptedContent);
    }

    public static MimeEntity parseEntity(byte[] content) throws HttpException {

        try {
            InputStream is = new ByteArrayInputStream(content);
            AS2SessionInputBuffer inbuffer = new AS2SessionInputBuffer(new BasicHttpTransportMetrics(), DEFAULT_BUFFER_SIZE);

            // Read Text Report Body Part Headers
            Header[] headers = AbstractMessageParser.parseHeaders(inbuffer, is, -1, -1, BasicLineParser.INSTANCE,
                    new ArrayList<>());

            // Get Content-Type and Content-Transfer-Encoding
            ContentType entityContentType = null;
            String entityContentTransferEncoding = null;
            for (Header header : headers) {
                if (header.getName().equalsIgnoreCase(AS2Header.CONTENT_TYPE)) {
                    entityContentType = ContentType.parse(header.getValue());
                } else if (header.getName().equalsIgnoreCase(AS2Header.CONTENT_TRANSFER_ENCODING)) {
                    entityContentTransferEncoding = header.getValue();
                }
            }
            if (entityContentType == null) {
                throw new HttpException("Failed to find Content-Type header in enveloped entity");
            }

            MimeEntity entity
                    = parseEntityBody(inbuffer, is, null, entityContentType, entityContentTransferEncoding, "", headers);
            Objects.requireNonNull(entity, "Trying to parse entity body resulted in a null MimeEntity");
            entity.removeAllHeaders();
            entity.setHeaders(headers);

            return entity;
        } catch (Exception e) {
            throw new HttpException("Failed to parse entity", e);
        }
    }

    public static byte[] uncompressData(byte[] compressedData, InputExpanderProvider expanderProvider)
            throws HttpException {
        try {
            CMSCompressedData cmsCompressedData = new CMSCompressedData(compressedData);
            return cmsCompressedData.getContent(expanderProvider);
        } catch (CMSException e) {
            throw new HttpException("Failed to decompress data", e);
        }
    }

    public static byte[] decryptData(byte[] encryptedData, PrivateKey privateKey) throws HttpException {
        try {
            // Create enveloped data from encrypted data
            CMSEnvelopedData cmsEnvelopedData = new CMSEnvelopedData(encryptedData);

            // Extract recipient information form enveloped data.
            RecipientInformationStore recipientsInformationStore = cmsEnvelopedData.getRecipientInfos();
            Collection<RecipientInformation> recipients = recipientsInformationStore.getRecipients();
            Iterator<RecipientInformation> it = recipients.iterator();

            // Decrypt if enveloped data contains recipient information
            if (it.hasNext()) {
                // Create recipient from private key.
                Recipient recipient = new JceKeyTransEnvelopedRecipient(privateKey);

                // Extract decrypted data from recipient information
                RecipientInformation recipientInfo = it.next();
                return recipientInfo.getContent(recipient);
            }
        } catch (CMSException e) {
            throw new AS2DecryptionException("Failed to decrypt data", e);
        }

        throw new AS2DecryptionException("Failed to decrypt data: bno recipient information");
    }

    private static void parseApplicationPkcs7MimeCompressedEntity(
            HttpMessage message, InputStream is, AS2SessionInputBuffer inBuffer, ContentType contentType,
            String contentTransferEncoding)
            throws HttpException {
        ApplicationPkcs7MimeCompressedDataEntity applicationPkcs7MimeCompressedDataEntity = null;

        ObjectHelper.notNull(message, "message");
        ObjectHelper.notNull(inBuffer, "inBuffer");

        HttpEntity entity = ObjectHelper.notNull(EntityUtils.getMessageEntity(message), "message entity");

        if (entity instanceof ApplicationPkcs7MimeCompressedDataEntity) {
            // already parsed
            return;
        }

        Args.check(entity.isStreaming(), "Message entity can not be parsed: entity is not streaming");

        try {

            applicationPkcs7MimeCompressedDataEntity
                    = parseApplicationPkcs7MimeCompressedDataEntityBody(inBuffer, is, null, contentType,
                            contentTransferEncoding);
            applicationPkcs7MimeCompressedDataEntity.setMainBody(true);

            EntityUtils.setMessageEntity(message, applicationPkcs7MimeCompressedDataEntity);

        } catch (Exception e) {
            throw new HttpException("Failed to parse entity content", e);
        }
    }

    private static void parseApplicationPkcs7MimeEnvelopedEntity(
            HttpMessage message, InputStream is, AS2SessionInputBuffer inBuffer, ContentType contentType,
            String contentTransferEncoding)
            throws HttpException {
        ApplicationPkcs7MimeEnvelopedDataEntity applicationPkcs7MimeEnvelopedDataEntity = null;

        ObjectHelper.notNull(message, "message");
        ObjectHelper.notNull(inBuffer, "inBuffer");

        HttpEntity entity = ObjectHelper.notNull(EntityUtils.getMessageEntity(message), "message entity");

        if (entity instanceof ApplicationPkcs7MimeCompressedDataEntity) {
            // already parsed
            return;
        }

        Args.check(entity.isStreaming(), "Message entity can not be parsed: entity is not streaming");

        try {

            applicationPkcs7MimeEnvelopedDataEntity
                    = parseApplicationPkcs7MimeEnvelopedDataEntityBody(inBuffer, is, null, contentType,
                            contentTransferEncoding);
            applicationPkcs7MimeEnvelopedDataEntity.setMainBody(true);

            EntityUtils.setMessageEntity(message, applicationPkcs7MimeEnvelopedDataEntity);

        } catch (Exception e) {
            throw new HttpException("Failed to parse entity content", e);
        }
    }

    private static void parseMultipartSignedEntity(
            HttpMessage message, InputStream is, AS2SessionInputBuffer inBuffer, String boundary, String charsetName,
            String contentTransferEncoding)
            throws HttpException {
        MultipartSignedEntity multipartSignedEntity = null;

        ObjectHelper.notNull(message, "message");
        ObjectHelper.notNull(inBuffer, "inBuffer");
        ObjectHelper.notNull(boundary, "boundary");
        ObjectHelper.notNull(charsetName, "charsetName");

        HttpEntity entity = ObjectHelper.notNull(EntityUtils.getMessageEntity(message), "message entity");

        if (entity instanceof MultipartSignedEntity) {
            // already parsed
            return;
        }

        Args.check(entity.isStreaming(), "Message entity can not be parsed: entity is not streaming");

        try {

            // Get Micalg Value
            String micalg = HttpMessageUtils.getParameterValue(message, AS2Header.CONTENT_TYPE, "micalg");
            if (micalg == null) {
                throw new HttpException("Failed to retrieve 'micalg' parameter from content type header");
            }

            multipartSignedEntity
                    = parseMultipartSignedEntityBody(inBuffer, is, boundary, micalg, charsetName, contentTransferEncoding);
            multipartSignedEntity.setMainBody(true);

            EntityUtils.setMessageEntity(message, multipartSignedEntity);

        } catch (HttpException e) {
            throw e;
        } catch (Exception e) {
            throw new HttpException("Failed to parse entity content", e);
        }
    }

    private static void parseApplicationEDIEntity(
            HttpMessage message, InputStream is, AS2SessionInputBuffer inBuffer, ContentType contentType,
            String contentTransferEncoding)
            throws HttpException {
        ApplicationEntity applicationEntity = null;

        ObjectHelper.notNull(message, "message");
        ObjectHelper.notNull(inBuffer, "inBuffer");

        HttpEntity entity = ObjectHelper.notNull(EntityUtils.getMessageEntity(message), "message entity");

        if (entity instanceof ApplicationEntity) {
            // already parsed
            return;
        }

        Args.check(entity.isStreaming(), "Message entity can not be parsed: entity is not streaming");

        try {

            applicationEntity = parseEDIEntityBody(inBuffer, is, null, contentType, contentTransferEncoding, "");
            applicationEntity.setMainBody(true);

            EntityUtils.setMessageEntity(message, applicationEntity);

        } catch (Exception e) {
            throw new HttpException("Failed to parse entity content", e);
        }
    }

    private static void parseMessageDispositionNotificationReportEntity(
            HttpMessage message, InputStream is, AS2SessionInputBuffer inBuffer, String boundary, String charsetName,
            String contentTransferEncoding)
            throws HttpException {
        DispositionNotificationMultipartReportEntity dispositionNotificationMultipartReportEntity = null;

        ObjectHelper.notNull(message, "message");
        ObjectHelper.notNull(inBuffer, "inBuffer");
        ObjectHelper.notNull(boundary, "boundary");
        ObjectHelper.notNull(charsetName, "charsetName");
        HttpEntity entity = ObjectHelper.notNull(EntityUtils.getMessageEntity(message), "message entity");

        if (entity instanceof DispositionNotificationMultipartReportEntity) {
            // already parsed
            return;
        }

        Args.check(entity.isStreaming(), "Message entity can not be parsed: entity is not streaming");

        try {

            dispositionNotificationMultipartReportEntity
                    = parseMultipartReportEntityBody(inBuffer, is, boundary, charsetName, contentTransferEncoding);

            EntityUtils.setMessageEntity(message, dispositionNotificationMultipartReportEntity);

        } catch (Exception e) {
            throw new HttpException("Failed to parse entity content", e);
        }
    }

    /**
     * Parses message's entity and replaces it with mime entity.
     *
     * @param  message       - message whose entity is parsed.
     * @throws HttpException when things go wrong.
     */
    public static void parseAS2MessageEntity(HttpMessage message) throws HttpException {
        if (EntityUtils.hasEntity(message)) {
            HttpEntity entity = ObjectHelper.notNull(EntityUtils.getMessageEntity(message), "message entity");

            if (entity instanceof MimeEntity) {
                // already parsed
                return;
            }

            try {
                // Determine Content Type of Message
                String contentTypeStr = HttpMessageUtils.getHeaderValue(message, AS2Header.CONTENT_TYPE);
                if (contentTypeStr == null) {
                    // contentTypeStr can be null when dispositionNotificationTo isn't set
                    return;
                }
                doParseAS2MessageEntity(message, contentTypeStr, entity);
            } catch (HttpException e) {
                throw e;
            } catch (Exception e) {
                throw new HttpException("Failed to parse entity content", e);
            }
        }

    }

    private static void doParseAS2MessageEntity(HttpMessage message, String contentTypeStr, HttpEntity entity)
            throws HttpException, IOException {
        ContentType contentType = ContentType.parse(contentTypeStr);

        // Determine Charset
        String charsetName = StandardCharsets.US_ASCII.name();
        Charset charset = contentType.getCharset();
        if (charset != null) {
            charsetName = charset.name();
        }

        // Get any Boundary Value
        String boundary = HttpMessageUtils.getParameterValue(message, AS2Header.CONTENT_TYPE, "boundary");

        // Determine content transfer encoding
        String contentTransferEncoding
                = HttpMessageUtils.getHeaderValue(message, AS2Header.CONTENT_TRANSFER_ENCODING);

        AS2SessionInputBuffer inBuffer = new AS2SessionInputBuffer(
                new BasicHttpTransportMetrics(), 8 * 1024);

        parseByMimeType(message, contentType, entity, inBuffer, contentTransferEncoding, boundary, charsetName);
    }

    private static void parseByMimeType(
            HttpMessage message, ContentType contentType, HttpEntity entity, AS2SessionInputBuffer inBuffer,
            String contentTransferEncoding, String boundary, String charsetName)
            throws HttpException, IOException {
        switch (contentType.getMimeType().toLowerCase()) {
            case AS2MimeType.APPLICATION_EDIFACT:
            case AS2MimeType.APPLICATION_EDI_X12:
            case AS2MimeType.APPLICATION_EDI_CONSENT:
                parseApplicationEDIEntity(message, entity.getContent(), inBuffer, contentType, contentTransferEncoding);
                break;
            case AS2MimeType.MULTIPART_SIGNED:
                parseMultipartSignedEntity(message, entity.getContent(), inBuffer, boundary, charsetName,
                        contentTransferEncoding);
                break;
            case AS2MimeType.APPLICATION_PKCS7_MIME:
                switch (contentType.getParameter("smime-type")) {
                    case "compressed-data":
                        parseApplicationPkcs7MimeCompressedEntity(message, entity.getContent(), inBuffer, contentType,
                                contentTransferEncoding);
                        break;
                    case "enveloped-data":
                        parseApplicationPkcs7MimeEnvelopedEntity(message, entity.getContent(), inBuffer, contentType,
                                contentTransferEncoding);
                        break;
                    default:
                }
                break;
            case AS2MimeType.MULTIPART_REPORT:
                parseMessageDispositionNotificationReportEntity(message, entity.getContent(), inBuffer, boundary,
                        charsetName,
                        contentTransferEncoding);
                break;
            default:
                break;
        }
    }

    public static MultipartSignedEntity parseMultipartSignedEntityBody(
            AS2SessionInputBuffer inbuffer,
            InputStream is,
            String boundary,
            String micalg,
            String charsetName,
            String contentTransferEncoding)
            throws ParseException {
        CharsetDecoder previousDecoder = inbuffer.getCharsetDecoder();

        try {

            if (charsetName == null) {
                charsetName = StandardCharsets.US_ASCII.name();
            }
            Charset charset = Charset.forName(charsetName);
            CharsetDecoder charsetDecoder = charset.newDecoder();

            inbuffer.setCharsetDecoder(charsetDecoder);

            NameValuePair[] parameters = new NameValuePair[] {
                    new BasicNameValuePair("protocol", AS2MimeType.APPLICATION_PKCS7_SIGNATURE),
                    new BasicNameValuePair("boundary", boundary), new BasicNameValuePair("micalg", micalg),
                    new BasicNameValuePair("charset", charsetName) };
            ContentType contentType = ContentType.create(AS2MimeType.MULTIPART_SIGNED, parameters);
            MultipartSignedEntity multipartSignedEntity
                    = new MultipartSignedEntity(contentType, contentTransferEncoding, boundary, false);

            // Skip Preamble and Start Boundary line
            skipPreambleAndStartBoundary(inbuffer, is, boundary);

            //
            // Parse Signed Entity Part
            //

            // Read Text Report Body Part Headers
            Header[] headers = AbstractMessageParser.parseHeaders(inbuffer, is, -1, -1, BasicLineParser.INSTANCE,
                    new ArrayList<>());

            // Get Content-Type and Content-Transfer-Encoding
            ContentType signedEntityContentType = null;
            String signedEntityContentTransferEncoding = null;
            for (Header header : headers) {
                if (header.getName().equalsIgnoreCase(AS2Header.CONTENT_TYPE)) {
                    signedEntityContentType = ContentType.parse(header.getValue());
                } else if (header.getName().equalsIgnoreCase(AS2Header.CONTENT_TRANSFER_ENCODING)) {
                    signedEntityContentTransferEncoding = header.getValue();
                }
            }
            if (signedEntityContentType == null) {
                throw new HttpException("Failed to find Content-Type header in signed entity body part");
            }

            MimeEntity signedEntity = parseEntityBody(inbuffer, is, boundary, signedEntityContentType,
                    signedEntityContentTransferEncoding, "", headers);
            signedEntity.removeAllHeaders();
            signedEntity.setHeaders(headers);
            multipartSignedEntity.addPart(signedEntity);

            //
            // End Signed Entity Part

            //
            // Parse Signature Body Part
            //

            // Read Signature Body Part Headers
            headers = AbstractMessageParser.parseHeaders(inbuffer, is, -1, -1, BasicLineParser.INSTANCE,
                    new ArrayList<>());

            // Get Content-Type and Content-Transfer-Encoding
            ContentType signatureContentType = null;
            String signatureContentTransferEncoding = null;
            for (Header header : headers) {
                if (header.getName().equalsIgnoreCase(AS2Header.CONTENT_TYPE)) {
                    signatureContentType = ContentType.parse(header.getValue());
                } else if (header.getName().equalsIgnoreCase(AS2Header.CONTENT_TRANSFER_ENCODING)) {
                    signatureContentTransferEncoding = header.getValue();
                }
            }
            if (signatureContentType == null) {
                throw new HttpException("Failed to find Content-Type header in signature body part");
            }
            if (!ContentTypeUtils.isPkcs7SignatureType(signatureContentType)) {
                throw new HttpException(
                        "Invalid content type '" + signatureContentType.getMimeType() + "' for signature body part");
            }

            ApplicationPkcs7SignatureEntity applicationPkcs7SignatureEntity = parseApplicationPkcs7SignatureEntityBody(inbuffer,
                    is, boundary, signatureContentType, signatureContentTransferEncoding);
            applicationPkcs7SignatureEntity.removeAllHeaders();
            applicationPkcs7SignatureEntity.setHeaders(headers);
            multipartSignedEntity.addPart(applicationPkcs7SignatureEntity);

            //
            // End Signature Body Part

            return multipartSignedEntity;

        } catch (Exception e) {
            ParseException parseException = new ParseException("failed to parse text entity");
            parseException.initCause(e);
            throw parseException;
        } finally {
            inbuffer.setCharsetDecoder(previousDecoder);
        }
    }

    public static DispositionNotificationMultipartReportEntity parseMultipartReportEntityBody(
            AS2SessionInputBuffer inbuffer,
            InputStream is,
            String boundary,
            String charsetName,
            String contentTransferEncoding)
            throws ParseException {
        CharsetDecoder previousDecoder = inbuffer.getCharsetDecoder();

        try {

            if (charsetName == null) {
                charsetName = StandardCharsets.US_ASCII.name();
            }
            Charset charset = Charset.forName(charsetName);
            CharsetDecoder charsetDecoder = charset.newDecoder();

            inbuffer.setCharsetDecoder(charsetDecoder);

            DispositionNotificationMultipartReportEntity dispositionNotificationMultipartReportEntity
                    = new DispositionNotificationMultipartReportEntity(boundary, contentTransferEncoding, false);

            // Skip Preamble and Start Boundary line
            skipPreambleAndStartBoundary(inbuffer, is, boundary);

            //
            // Parse Text Report Body Part
            //

            // Read Text Report Body Part Headers
            Header[] headers = AbstractMessageParser.parseHeaders(inbuffer, is, -1, -1, BasicLineParser.INSTANCE,
                    new ArrayList<>());

            // Get Content-Type and Content-Transfer-Encoding
            ContentType textReportContentType = null;
            String textReportContentTransferEncoding = null;
            for (Header header : headers) {
                if (header.getName().equalsIgnoreCase(AS2Header.CONTENT_TYPE)) {
                    textReportContentType = ContentType.parse(header.getValue());
                } else if (header.getName().equalsIgnoreCase(AS2Header.CONTENT_TRANSFER_ENCODING)) {
                    textReportContentTransferEncoding = header.getValue();
                }
            }
            if (textReportContentType == null) {
                throw new HttpException("Failed to find Content-Type header in EDI message body part");
            }
            if (!textReportContentType.getMimeType().equalsIgnoreCase(AS2MimeType.TEXT_PLAIN)) {
                throw new HttpException(
                        "Invalid content type '" + textReportContentType.getMimeType()
                                        + "' for first body part of disposition notification");
            }

            String textReportCharsetName = textReportContentType.getCharset() == null
                    ? StandardCharsets.US_ASCII.name() : textReportContentType.getCharset().name();
            TextPlainEntity textReportEntity
                    = parseTextPlainEntityBody(inbuffer, is, boundary, textReportCharsetName,
                            textReportContentTransferEncoding);
            textReportEntity.setHeaders(headers);
            dispositionNotificationMultipartReportEntity.addPart(textReportEntity);

            //
            // End Text Report Body Part

            //
            // Parse Disposition Notification Body Part
            //

            // Read Disposition Notification Body Part Headers
            headers = AbstractMessageParser.parseHeaders(inbuffer, is, -1, -1, BasicLineParser.INSTANCE,
                    new ArrayList<>());

            // Get Content-Type and Content-Transfer-Encoding
            ContentType dispositionNotificationContentType = null;
            for (Header header : headers) {
                if (header.getName().equalsIgnoreCase(AS2Header.CONTENT_TYPE)) {
                    dispositionNotificationContentType = ContentType.parse(header.getValue());
                }
            }
            if (dispositionNotificationContentType == null) {
                throw new HttpException("Failed to find Content-Type header in body part");
            }
            if (!dispositionNotificationContentType.getMimeType()
                    .equalsIgnoreCase(AS2MimeType.MESSAGE_DISPOSITION_NOTIFICATION)) {
                throw new HttpException(
                        "Invalid content type '" + dispositionNotificationContentType.getMimeType()
                                        + "' for second body part of disposition notification");
            }

            String dispositionNotificationCharsetName = dispositionNotificationContentType.getCharset() == null
                    ? StandardCharsets.US_ASCII.name() : dispositionNotificationContentType.getCharset().name();
            AS2MessageDispositionNotificationEntity messageDispositionNotificationEntity
                    = parseMessageDispositionNotificationEntityBody(
                            inbuffer, is, boundary, dispositionNotificationCharsetName);
            messageDispositionNotificationEntity.setHeaders(headers);
            dispositionNotificationMultipartReportEntity.addPart(messageDispositionNotificationEntity);

            //
            // End Disposition Notification Body Part

            return dispositionNotificationMultipartReportEntity;
        } catch (Exception e) {
            ParseException parseException = new ParseException("failed to parse text entity");
            parseException.initCause(e);
            throw parseException;
        } finally {
            inbuffer.setCharsetDecoder(previousDecoder);
        }

    }

    public static TextPlainEntity parseTextPlainEntityBody(
            AS2SessionInputBuffer inbuffer,
            InputStream is,
            String boundary,
            String charsetName,
            String contentTransferEncoding)
            throws ParseException {
        CharsetDecoder previousDecoder = inbuffer.getCharsetDecoder();

        try {

            if (charsetName == null) {
                charsetName = StandardCharsets.US_ASCII.name();
            }
            Charset charset = Charset.forName(charsetName);
            CharsetDecoder charsetDecoder = charset.newDecoder();

            inbuffer.setCharsetDecoder(charsetDecoder);

            String text = parseBodyPartText(inbuffer, is, boundary);
            if (contentTransferEncoding != null) {
                text = EntityUtils.decode(text, charset, contentTransferEncoding);
            }
            return new TextPlainEntity(text, charsetName, contentTransferEncoding, false);
        } catch (Exception e) {
            ParseException parseException = new ParseException("failed to parse text entity");
            parseException.initCause(e);
            throw parseException;
        } finally {
            inbuffer.setCharsetDecoder(previousDecoder);
        }
    }

    public static AS2MessageDispositionNotificationEntity parseMessageDispositionNotificationEntityBody(
            AS2SessionInputBuffer inbuffer,
            InputStream is,
            String boundary,
            String charsetName)
            throws ParseException {
        CharsetDecoder previousDecoder = inbuffer.getCharsetDecoder();

        try {

            if (charsetName == null) {
                charsetName = StandardCharsets.US_ASCII.name();
            }
            Charset charset = Charset.forName(charsetName);
            CharsetDecoder charsetDecoder = charset.newDecoder();

            inbuffer.setCharsetDecoder(charsetDecoder);

            List<CharArrayBuffer> dispositionNotificationFields = parseBodyPartFields(inbuffer, is, boundary,
                    BasicLineParser.INSTANCE, new ArrayList<>());

            AS2MessageDispositionNotificationEntity as2MessageDispositionNotificationEntity
                    = DispositionNotificationContentUtils.parseDispositionNotification(dispositionNotificationFields);
            return as2MessageDispositionNotificationEntity;
        } catch (Exception e) {
            ParseException parseException = new ParseException("failed to parse MDN entity");
            parseException.initCause(e);
            throw parseException;
        } finally {
            inbuffer.setCharsetDecoder(previousDecoder);
        }
    }

    public static MimeEntity parseEntityBody(
            AS2SessionInputBuffer inbuffer,
            InputStream is,
            String boundary,
            ContentType entityContentType,
            String contentTransferEncoding,
            String filename,
            Header[] headers)
            throws ParseException {
        CharsetDecoder previousDecoder = inbuffer.getCharsetDecoder();

        try {
            Charset charset = entityContentType.getCharset();
            if (charset == null) {
                charset = StandardCharsets.US_ASCII;
            }
            CharsetDecoder charsetDecoder = charset.newDecoder();

            inbuffer.setCharsetDecoder(charsetDecoder);

            MimeEntity entity = null;
            switch (entityContentType.getMimeType().toLowerCase()) {
                case AS2MimeType.APPLICATION_EDIFACT:
                case AS2MimeType.APPLICATION_EDI_X12:
                case AS2MimeType.APPLICATION_EDI_CONSENT:
                case AS2MimeType.APPLICATION_XML:
                    entity = parseEDIEntityBody(inbuffer, is, boundary, entityContentType, contentTransferEncoding, filename);
                    break;
                case AS2MimeType.MULTIPART_SIGNED:
                    String multipartSignedBoundary = AS2HeaderUtils.getParameterValue(headers,
                            AS2Header.CONTENT_TYPE, "boundary");
                    String micalg = AS2HeaderUtils.getParameterValue(headers, AS2Header.CONTENT_TYPE, "micalg");
                    entity = parseMultipartSignedEntityBody(inbuffer, is, multipartSignedBoundary, micalg, charset.name(),
                            contentTransferEncoding);
                    skipToBoundary(inbuffer, is, boundary);
                    break;
                case AS2MimeType.MESSAGE_DISPOSITION_NOTIFICATION:
                    entity = parseMessageDispositionNotificationEntityBody(inbuffer, is, boundary, charset.name());
                    break;
                case AS2MimeType.MULTIPART_REPORT:
                    String multipartReportBoundary = AS2HeaderUtils.getParameterValue(headers,
                            AS2Header.CONTENT_TYPE, "boundary");
                    entity = parseMultipartReportEntityBody(inbuffer, is, multipartReportBoundary, charset.name(),
                            contentTransferEncoding);
                    skipToBoundary(inbuffer, is, boundary);
                    break;
                case AS2MimeType.TEXT_PLAIN:
                    entity = parseTextPlainEntityBody(inbuffer, is, boundary, charset.name(), contentTransferEncoding);
                    break;
                case AS2MimeType.APPLICATION_PKCS7_SIGNATURE:
                    entity = parseApplicationPkcs7SignatureEntityBody(inbuffer, is, boundary, entityContentType,
                            contentTransferEncoding);
                    break;
                case AS2MimeType.APPLICATION_PKCS7_MIME:
                    switch (entityContentType.getParameter("smime-type")) {
                        case "compressed-data":
                            entity = parseApplicationPkcs7MimeCompressedDataEntityBody(inbuffer, is, boundary,
                                    entityContentType,
                                    contentTransferEncoding);
                            break;
                        case "enveloped-data":
                            entity = parseApplicationPkcs7MimeEnvelopedDataEntityBody(inbuffer, is, boundary, entityContentType,
                                    contentTransferEncoding);
                            break;
                        default:
                            break;
                    }
                    break;
                default:
                    break;
            }

            return entity;

        } catch (Exception e) {
            ParseException parseException = new ParseException("failed to parse EDI entity");
            parseException.initCause(e);
            throw parseException;
        } finally {
            inbuffer.setCharsetDecoder(previousDecoder);
        }

    }

    public static ApplicationEntity parseEDIEntityBody(
            AS2SessionInputBuffer inbuffer,
            InputStream is,
            String boundary,
            ContentType ediMessageContentType,
            String contentTransferEncoding,
            String filename)
            throws ParseException {
        CharsetDecoder previousDecoder = inbuffer.getCharsetDecoder();

        try {
            Charset charset = ediMessageContentType.getCharset();
            if (charset == null) {
                charset = StandardCharsets.US_ASCII;
            }
            CharsetDecoder charsetDecoder = charset.newDecoder();

            inbuffer.setCharsetDecoder(charsetDecoder);

            byte[] ediMessageBodyPartContentBytes
                    = parseBodyPartBytes(inbuffer, is, boundary, ediMessageContentType, contentTransferEncoding);

            return EntityUtils.createEDIEntity(ediMessageBodyPartContentBytes,
                    ediMessageContentType, contentTransferEncoding, false, filename);
        } catch (Exception e) {
            ParseException parseException = new ParseException("failed to parse EDI entity");
            parseException.initCause(e);
            throw parseException;
        } finally {
            inbuffer.setCharsetDecoder(previousDecoder);
        }
    }

    public static ApplicationPkcs7SignatureEntity parseApplicationPkcs7SignatureEntityBody(
            AS2SessionInputBuffer inbuffer,
            InputStream is,
            String boundary,
            ContentType contentType,
            String contentTransferEncoding)
            throws ParseException {

        CharsetDecoder previousDecoder = inbuffer.getCharsetDecoder();

        try {
            byte[] signature = parseBodyPartBytes(inbuffer, is, boundary, contentType, contentTransferEncoding);

            Charset charset = contentType.getCharset();
            if (charset == null) {
                charset = StandardCharsets.US_ASCII;
            }
            String charsetName = charset.toString();
            return new ApplicationPkcs7SignatureEntity(signature, charsetName, contentTransferEncoding, false);
        } catch (Exception e) {
            ParseException parseException = new ParseException("failed to parse PKCS7 Signature entity");
            parseException.initCause(e);
            throw parseException;
        } finally {
            inbuffer.setCharsetDecoder(previousDecoder);
        }
    }

    public static ApplicationPkcs7MimeEnvelopedDataEntity parseApplicationPkcs7MimeEnvelopedDataEntityBody(
            AS2SessionInputBuffer inbuffer,
            InputStream is,
            String boundary,
            ContentType contentType,
            String contentTransferEncoding)
            throws ParseException {

        CharsetDecoder previousDecoder = inbuffer.getCharsetDecoder();

        try {
            byte[] encryptedContent = parseBodyPartBytes(inbuffer, is, boundary, contentType, contentTransferEncoding);
            return new ApplicationPkcs7MimeEnvelopedDataEntity(encryptedContent, contentTransferEncoding, false);
        } catch (Exception e) {
            ParseException parseException = new ParseException("failed to parse PKCS7 Mime entity");
            parseException.initCause(e);
            throw parseException;
        } finally {
            inbuffer.setCharsetDecoder(previousDecoder);
        }
    }

    public static ApplicationPkcs7MimeCompressedDataEntity parseApplicationPkcs7MimeCompressedDataEntityBody(
            AS2SessionInputBuffer inbuffer,
            InputStream is,
            String boundary,
            ContentType contentType,
            String contentTransferEncoding)
            throws ParseException {

        CharsetDecoder previousDecoder = inbuffer.getCharsetDecoder();

        try {
            byte[] compressedContent = parseBodyPartBytes(inbuffer, is, boundary, contentType, contentTransferEncoding);
            return new ApplicationPkcs7MimeCompressedDataEntity(compressedContent, contentTransferEncoding, false);
        } catch (Exception e) {
            ParseException parseException = new ParseException("failed to parse PKCS7 Mime entity");
            parseException.initCause(e);
            throw parseException;
        } finally {
            inbuffer.setCharsetDecoder(previousDecoder);
        }
    }

    public static byte[] parseBodyPartBytes(
            final AS2SessionInputBuffer inbuffer,
            InputStream is,
            final String boundary,
            ContentType contentType,
            String contentTransferEncoding)
            throws IOException, CamelException, DecoderException {

        Charset charset = contentType.getCharset();
        if (charset != null) {
            CharsetDecoder charsetDecoder = charset.newDecoder();
            inbuffer.setCharsetDecoder(charsetDecoder);
        } else {
            inbuffer.setCharsetDecoder(null);
        }

        String bodyContent = parseBodyPartText(inbuffer, is, boundary);

        byte[] bodyContentBytes;
        if (charset != null) {
            bodyContentBytes = bodyContent.getBytes(charset);
        } else {
            bodyContentBytes = new byte[bodyContent.length()];
            for (int i = 0; i < bodyContent.length(); i++) {
                bodyContentBytes[i] = (byte) bodyContent.charAt(i);
            }
        }

        return EntityUtils.decode(bodyContentBytes, contentTransferEncoding);
    }

    public static String parseBodyPartText(
            final AS2SessionInputBuffer inbuffer,
            InputStream is,
            final String boundary)
            throws IOException {
        CharArrayBuffer buffer = new CharArrayBuffer(DEFAULT_BUFFER_SIZE);
        CharArrayBuffer line = new CharArrayBuffer(DEFAULT_BUFFER_SIZE);
        while (true) {
            final int l = inbuffer.readLine(line, is);
            if (l == -1) {
                break;
            }

            if (boundary != null && isBoundaryDelimiter(line, null, boundary)) {
                // remove last CRLF from buffer which belongs to boundary
                int length = buffer.length();
                buffer.setLength(length - 2);
                break;
            }

            buffer.append(line);
            if (inbuffer.isLastLineReadEnrichedByCarriageReturn()) {
                buffer.append((char) CR);
            }
            if (inbuffer.isLastLineReadTerminatedByLineFeed()) {
                buffer.append((char) LF);
            }
            line.clear();
        }

        return buffer.toString();
    }

    public static List<CharArrayBuffer> parseBodyPartFields(
            final AS2SessionInputBuffer inbuffer,
            final InputStream is,
            final String boundary,
            final LineParser parser,
            final List<CharArrayBuffer> fields)
            throws IOException {
        ObjectHelper.notNull(parser, "parser");
        ObjectHelper.notNull(fields, "fields");
        CharArrayBuffer current = null;
        CharArrayBuffer previous = null;
        while (true) {

            if (current == null) {
                current = new CharArrayBuffer(64);
            }

            final int l = inbuffer.readLine(current, is);
            if (l == -1 || current.length() < 1) {
                break;
            }

            if (boundary != null && isBoundaryDelimiter(current, null, boundary)) {
                break;
            }

            // check if current line part of folded headers
            if ((current.charAt(0) == ' ' || current.charAt(0) == '\t') && previous != null) {
                // we have continuation of folded header : append value
                int i = 0;
                while (i < current.length()) {
                    final char ch = current.charAt(i);
                    if (ch != ' ' && ch != '\t') {
                        break;
                    }
                    i++;
                }

                // Just append current line to previous line
                previous.append(' ');
                previous.append(current, i, current.length() - i);

                // leave current line buffer for reuse for next header
                current.clear();
            } else {
                fields.add(current);
                previous = current;
                current = null;
            }
        }
        return fields;
    }
}
