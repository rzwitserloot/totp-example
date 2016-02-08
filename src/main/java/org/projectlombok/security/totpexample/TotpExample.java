package org.projectlombok.security.totpexample;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

import freemarker.template.Configuration;
import freemarker.template.TemplateExceptionHandler;

/**
 * There is nothing particularly special about this code; it just launches jetty
 * pre-configured to port 8837 and with our servlets.
 * 
 * This file should not be in your project.
 * 
 * The servlets that this application serves up are:
 * 
 * /signup         SignupServlet
 * /login          LoginServlet
 * .... TODO
 * 
 * Check those source files, in that order, to learn about how to implement TOTP in your own project.
 */
public class TotpExample {
	public static void main(String[] args) throws Exception {
		Server server = new Server(8837);
		ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
		context.setContextPath("/");
		Configuration templateConfiguration = createTemplateConfiguration();
		context.addServlet(new ServletHolder(new LoginServlet(templateConfiguration)), "/login");
		context.addServlet(new ServletHolder(new SignupServlet(templateConfiguration)), "/signup");
		server.setHandler(context);
		
		server.start();
		server.join();
	}
	
	private static Configuration createTemplateConfiguration() {
		Configuration cfg = new Configuration(Configuration.VERSION_2_3_23);
		cfg.setClassLoaderForTemplateLoading(TotpExample.class.getClassLoader(), TotpExample.class.getPackage().getName().replace(".", "/"));
		cfg.setDefaultEncoding("UTF-8");
		cfg.setTemplateExceptionHandler(TemplateExceptionHandler.HTML_DEBUG_HANDLER); // SECURITY NOTE: You should use the TemplateExceptionHandler.RETHROW_HANDLER in production.
		return cfg;
	}
}
