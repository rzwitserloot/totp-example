package org.projectlombok.security.totpexample.servlets;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.projectlombok.security.totpexample.ResourcesHome;

/**
 * All the default mechanisms for serving static resources that jetty ships with do not allow finding
 * resources via {@code .getResourceAsStream} so we just serve it from our own servlet.
 * 
 * Every static resource we serve is only for demo purposes; you'd have your own fonts and styles and logos.
 * You don't need this servlet, nor do you need to copy parts of it, when implementing TOTP in your own web application.
 */
public class StaticFilesServlet extends HttpServlet {
	private static final Map<String, String> STATIC_RESOURCES;
	
	static {
		Map<String, String> m = new HashMap<>();
		m.put("/css", "text/css styles.css");
		m.put("/fonts/Roboto-Medium.ttf", "font/opentype fonts/Roboto-Medium.ttf");
		m.put("/fonts/Roboto-Regular.ttf", "font/opentype fonts/Roboto-Regular.ttf");
		STATIC_RESOURCES = Collections.unmodifiableMap(m);
	}
	
	@Override protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String file = request.getRequestURI();
		String resourceData = STATIC_RESOURCES.get(file);
		if (resourceData == null) {
			response.sendError(HttpServletResponse.SC_NOT_FOUND);
			return;
		}
		
		String[] parts = resourceData.split(" ", 2);
		try (InputStream in = ResourcesHome.class.getResourceAsStream(parts[1])) {
			response.setContentType(parts[0]);
			try (OutputStream out = response.getOutputStream()) {
				byte[] b = new byte[4096];
				while (true) {
					int r = in.read(b);
					if (r == -1) break;
					out.write(b, 0, r);
				}
			}
		}
	}
}
