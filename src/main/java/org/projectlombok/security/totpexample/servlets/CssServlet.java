package org.projectlombok.security.totpexample.servlets;

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

/**
 * This servlet serves up the styles.css file 
 */
public class CssServlet extends HttpServlet {
	private final Template stylesTemplate;
	
	public CssServlet(Configuration templates) throws IOException {
		this.stylesTemplate = templates.getTemplate("styles.css");
	}
	
	@Override protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		Map<String, Object> root = new HashMap<>();
		response.setContentType("text/css; charset=UTF-8");
		try (Writer out = response.getWriter()) {
			stylesTemplate.process(root, out);
		} catch (TemplateException e) {
			throw new ServletException("Template broken: styles.css", e);
		}
	}
}
