import { describe, expect, it } from "vitest";
import { PortalSettingsService } from "../../src/application/portal-settings-service";

describe("PortalSettingsService", () => {
  it("creates disabled web TLS defaults", () => {
    const settings = PortalSettingsService.createDefaultSettings();

    expect(settings.branding.logoDataUrl).toBe("");
    expect(settings.webTls.enabled).toBe(false);
    expect(settings.webTls.certPem).toBe("");
    expect(settings.webTls.keyPem).toBe("");
    expect(settings.webTls.passphrase).toBe("");
    expect(settings.webTls.redirectHttpEnabled).toBe(false);
    expect(settings.webTls.redirectHttpPort).toBe(80);
  });
});