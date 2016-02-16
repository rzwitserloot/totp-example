package org.projectlombok.security.totpexample.launcher;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.projectlombok.security.totpexample.Crypto;
import org.projectlombok.security.totpexample.SessionStore;
import org.projectlombok.security.totpexample.TemplatesHome;
import org.projectlombok.security.totpexample.Totp;
import org.projectlombok.security.totpexample.UserStore;
import org.projectlombok.security.totpexample.impl.DbBasedSessionStore;
import org.projectlombok.security.totpexample.impl.DbBasedUserStore;
import org.projectlombok.security.totpexample.servlets.ConfirmTotpServlet;
import org.projectlombok.security.totpexample.servlets.LoginServlet;
import org.projectlombok.security.totpexample.servlets.QrServlet;
import org.projectlombok.security.totpexample.servlets.SetupTotpServlet;
import org.projectlombok.security.totpexample.servlets.SignupServlet;

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
		
		Crypto crypto = new Crypto();
		Configuration templates = createTemplateConfiguration();
		SessionStore sessions = createSessionStore(crypto);
		UserStore users = createUserStore(crypto);
		Totp totp = new Totp(users, sessions, crypto);

		context.addServlet(new ServletHolder(new LoginServlet(templates)), "/login");
		context.addServlet(new ServletHolder(new SignupServlet(templates, sessions)), "/signup");
		context.addServlet(new ServletHolder(new SetupTotpServlet(templates, sessions, totp)), "/setup-totp");
		context.addServlet(new ServletHolder(new ConfirmTotpServlet(templates, sessions, totp)), "/confirm-totp");
		context.addServlet(new ServletHolder(new QrServlet(sessions)), "/qrcode");
		server.setHandler(context);
		
		server.start();
		server.join();
	}
	
	private static SessionStore createSessionStore(Crypto crypto) {
		return new DbBasedSessionStore(crypto);
	}
	
	private static UserStore createUserStore(Crypto crypto) {
		return new DbBasedUserStore(crypto);
	}
	
	private static Configuration createTemplateConfiguration() {
		Configuration cfg = new Configuration(Configuration.VERSION_2_3_23);
		cfg.setClassLoaderForTemplateLoading(TotpExample.class.getClassLoader(), TemplatesHome.class.getPackage().getName().replace(".", "/"));
		cfg.setDefaultEncoding("UTF-8");
		
		// SECURITY NOTE: You should use the TemplateExceptionHandler.RETHROW_HANDLER in production.
		cfg.setTemplateExceptionHandler(TemplateExceptionHandler.HTML_DEBUG_HANDLER);
		return cfg;
	}
}
