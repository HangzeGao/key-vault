import { expect, test } from "@playwright/test";

test("login layout does not overflow at desktop and narrow widths", async ({ page }) => {
  await page.goto("/ui/login");
  await expect(page.getByRole("button", { name: /Authenticate/i })).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
  expect(overflow).toBe(false);
  await expect(page).toHaveScreenshot(`login-${test.info().project.name}.png`, { fullPage: true });
});
