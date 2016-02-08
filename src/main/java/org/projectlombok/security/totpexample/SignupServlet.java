package org.projectlombok.security.totpexample;

import java.io.IOException;
import java.io.Writer;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;

public class SignupServlet extends HttpServlet {
	private final Template signupTemplate;
	
	public SignupServlet(Configuration templates) throws IOException {
		this.signupTemplate = templates.getTemplate("signup.html");
	}
	
	@Override protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		Map<String, Object> root = new HashMap<>();
		response.setContentType("text/html; charset=UTF-8");
		try (Writer out = response.getWriter()) {
			signupTemplate.process(root, out);
		} catch (TemplateException e) {
			throw new ServletException("Template broken: signup.html", e);
		}
	}
}
