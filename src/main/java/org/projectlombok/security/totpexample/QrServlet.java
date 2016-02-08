package org.projectlombok.security.totpexample;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

public class QrServlet extends HttpServlet {
	
	@Override protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		byte[] qrCodeImage = generateQrCodeForUri("https://projectlombok.org/");
		
		response.setContentType("image/png");
		
		// SECURITY NOTE: This Cache-Control header is not 'nice-to-have'. IT IS A REQUIREMENT.
		response.addHeader("Cache-Control", "no-store");
		
		try (OutputStream out = response.getOutputStream()) {
			out.write(qrCodeImage);
		}
	}

	private byte[] generateQrCodeForUri(String uri) {
		try {
			ByteArrayOutputStream stream = new ByteArrayOutputStream();
			BitMatrix matrix = new QRCodeWriter().encode(uri, BarcodeFormat.QR_CODE, 200, 200);
			MatrixToImageWriter.writeToStream(matrix, "PNG", stream);
			return stream.toByteArray();
		} catch (IOException | WriterException e) {
			// Given that this operation is entirely in memory, any such exceptions are indicative of bad input.
			throw new IllegalArgumentException("Invalid URI", e);
		}
	}
}
