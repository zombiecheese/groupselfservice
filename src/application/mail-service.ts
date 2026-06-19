import nodemailer from "nodemailer";
import { MailIntegrationSettings, PortalSettingsRepository } from "./contracts";

export interface MailMessage {
  to: string;
  subject: string;
  text: string;
  html?: string;
}

export class MailService {
  constructor(private readonly settingsRepository: PortalSettingsRepository) {}

  async send(message: MailMessage): Promise<void> {
    const settings = (await this.settingsRepository.get()).mail;
    if (!settings.enabled) {
      return;
    }

    if (settings.mode === "smtp") {
      await this.sendViaSmtp(settings, message);
      return;
    }

    await this.sendViaEntra(settings, message);
  }

  async sendTestMessage(to: string): Promise<void> {
    await this.send({
      to,
      subject: "Group Self Service test email",
      text: "This is a test email from the Group Self Service portal.",
    });
  }

  private async sendViaSmtp(settings: MailIntegrationSettings, message: MailMessage): Promise<void> {
    const useAuth = settings.smtp.requireAuth !== false && !!settings.smtp.username;
    const transport = nodemailer.createTransport({
      host: settings.smtp.host,
      port: settings.smtp.port,
      secure: settings.smtp.secure,
      ignoreTLS: settings.smtp.ignoreTls === true,
      auth: useAuth
        ? {
            user: settings.smtp.username,
            pass: settings.smtp.password,
          }
        : undefined,
      tls: settings.smtp.allowUntrustedTls
        ? { rejectUnauthorized: false }
        : undefined,
    });

    await transport.sendMail({
      from: settings.fromAddress,
      to: message.to,
      subject: message.subject,
      text: message.text,
      html: message.html,
    });
  }

  private async sendViaEntra(settings: MailIntegrationSettings, message: MailMessage): Promise<void> {
    if (!settings.entra.tenantId || !settings.entra.clientId || !settings.entra.clientSecret) {
      throw new Error("Entra mail settings are incomplete.");
    }

    const tokenResponse = await fetch(
      `https://login.microsoftonline.com/${settings.entra.tenantId}/oauth2/v2.0/token`,
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "client_credentials",
          client_id: settings.entra.clientId,
          client_secret: settings.entra.clientSecret,
          scope: "https://graph.microsoft.com/.default",
        }),
      }
    );

    if (!tokenResponse.ok) {
      throw new Error(`Failed to obtain Graph token: ${tokenResponse.status}`);
    }

    const tokenJson = (await tokenResponse.json()) as { access_token?: string };
    if (!tokenJson.access_token) {
      throw new Error("Graph token response missing access_token.");
    }

    const sender = settings.entra.senderUpn || settings.fromAddress;
    const sendUrl = `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(sender)}/sendMail`;

    const response = await fetch(sendUrl, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${tokenJson.access_token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        message: {
          subject: message.subject,
          body: {
            contentType: message.html ? "HTML" : "Text",
            content: message.html ?? message.text,
          },
          toRecipients: [
            {
              emailAddress: { address: message.to },
            },
          ],
          from: {
            emailAddress: { address: settings.fromAddress },
          },
        },
        saveToSentItems: false,
      }),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Graph sendMail failed: ${response.status} ${text}`);
    }
  }
}
