import { expect, test, type Page } from "@playwright/test";

test.use({ channel: process.env.THREATLENS_BROWSER_CHANNEL || undefined });

async function openTab(page: Page, name: string) {
  await page.mouse.move(8, 250);
  await page.getByRole("button", { name }).click();
}

test.beforeEach(async ({ page }) => {
  await page.goto("http://localhost:5173");
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
});

test("opens the live model and evidence tabs", async ({ page }) => {
  await openTab(page, "Evidence vault");
  await expect(page.getByRole("heading", { name: "Persisted evidence" })).toBeVisible();
  await expect(page.getByText(/Page 1 of/)).toBeVisible();
  await openTab(page, "Model intelligence");
  await expect(page.getByRole("heading", { name: "Model intelligence" })).toBeVisible();
});

test("submits checklist mode and displays the assistant response", async ({ page }) => {
  await page.route("**/api/v1/chat", async (route) => {
    expect(route.request().postDataJSON()).toMatchObject({ mode: "checklist", question: "Review login.failed" });
    await route.fulfill({ json: { answer: "Verify the source logs before escalating." } });
  });
  await openTab(page, "Investigation assistant");
  await page.getByLabel("Investigation output").selectOption("checklist");
  await page.getByPlaceholder("Ask about the evidence…").fill("Review login.failed");
  await page.getByRole("button", { name: "Generate" }).click();
  await expect(page.getByText("Verify the source logs before escalating.")).toBeVisible();
});
