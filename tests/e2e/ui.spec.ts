import { expect, test, type Page } from "@playwright/test";

const email = process.env.E2E_EMAIL ?? "admin@aegis.local";
const password = process.env.E2E_PASSWORD ?? "supersecretpassword";

async function login(page: Page) {
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: /Continue/ }).click();
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeHidden({
    timeout: 20_000,
  });
}

test("setup or login, then Hosts create", async ({ page }) => {
  await page.goto("/");
  const setup = page.getByRole("heading", { name: "Create the first admin" });
  const signin = page.getByRole("heading", { name: "Sign in" });
  await expect(setup.or(signin)).toBeVisible({ timeout: 30_000 });

  if (await setup.isVisible()) {
    await page.getByLabel("Name").fill("Admin");
    await page.getByLabel("Email").fill(email);
    await page.getByLabel("Password").fill(password);
    await page.getByLabel("Confirm").fill(password);
    await page.getByRole("button", { name: /Continue/ }).click();
    await expect(page.getByRole("heading", { name: "Get Aegis live" })).toBeVisible({
      timeout: 20_000,
    });
    await page.getByRole("button", { name: "Sign out" }).click();
    await login(page);
  } else {
    await login(page);
  }

  await page.goto("/hosts");
  await expect(page.getByRole("heading", { name: "Hosts" })).toBeVisible();
  await page.getByRole("button", { name: /Add host/ }).first().click();
  await expect(page.getByRole("heading", { name: "Add host" })).toBeVisible();
  await page.getByPlaceholder("app.example.com").fill("pw.local");
  await page.getByPlaceholder("10.0.0.5").fill("demo");
  await page.getByRole("radio", { name: "HTTP only" }).click();
  await page.getByRole("button", { name: "Create host" }).click();
  const row = page.getByRole("button", { name: "pw.local", exact: true });
  const dup = page.getByText(/already in use/i);
  await expect(row.or(dup)).toBeVisible({ timeout: 20_000 });
  if (await dup.isVisible()) {
    await page.getByRole("button", { name: "Cancel" }).click();
    await expect(row).toBeVisible();
  }
});
