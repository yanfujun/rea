import { expect, it } from "vitest";
import { analyzeJavaScriptSemantics } from "./javascriptSemanticAnalysis.js";
import {
  onlyBinding,
  onlyCallable,
} from "./javascriptSemanticAnalysis.fixture.js";
import { getterExpansionSource } from "../../../tests/fixtures/javascriptGetterExpansion.js";

it.each([10, 30])(
  "bounds permutations across %i unknown-key getters (#3839)",
  (count) => {
    const ir = analyzeJavaScriptSemantics(getterExpansionSource(count));
    expect(ir.coverage).toMatchObject({
      status: "partial",
      omittedCount: null,
      resourceLimits: ["getter-expansion"],
    });
    expect(onlyBinding(ir, "result").value).toMatchObject({
      status: "unknown",
      resourceLimit: "getter-expansion",
    });
    expect(onlyBinding(ir, "result").provenance).toMatchObject({
      status: "unknown",
      origins: [],
    });
    expect(ir.references).toContainEqual(
      expect.objectContaining({
        name: "shared",
        resolution: "resolved",
        bindingId: onlyBinding(ir, "shared").bindingId,
      }),
    );
    expect(onlyCallable(ir, "field0").returnCoverage).toMatchObject({
      status: "partial",
      omittedCount: null,
    });
    expect(ir.moduleLinks).toEqual([]);
    expect(ir.callSites).toEqual([]);
    expect(ir.limitations.join(" ")).toMatch(
      /Getter expansion budget exceeded/,
    );
  },
);

it("bounds static getter permutations with the same query budget", () => {
  const source = getterExpansionSource()
    .replaceAll("get ", "static get ")
    .replace("new Request().field0", "Request.field0");
  expect(analyzeJavaScriptSemantics(source).coverage).toMatchObject({
    status: "partial",
    resourceLimits: ["getter-expansion"],
  });
});

it("bounds inherited dynamic getters", () => {
  const source = getterExpansionSource().replace(
    "consume(new Request().field0)",
    "class Derived extends Request {} consume(new Derived().field0)",
  );
  expect(analyzeJavaScriptSemantics(source).coverage).toMatchObject({
    status: "partial",
    resourceLimits: ["getter-expansion"],
  });
});

it("limits deep acyclic getter chains before exhausting the native stack", () => {
  const getters = Array.from(
    { length: 600 },
    (_, index) => `get field${index}() { return this.field${index + 1}; }`,
  ).join("\n");
  const ir = analyzeJavaScriptSemantics(`
    class Request { ${getters} }
    consume(new Request().field0);
  `);
  expect(ir.coverage).toMatchObject({
    status: "partial",
    resourceLimits: ["getter-expansion"],
  });
});

it("starts a fresh budget for each independent property query", () => {
  const calls = "consume(new Box().value);\n".repeat(300);
  const ir = analyzeJavaScriptSemantics(`
    const shared = { x: 1 };
    class Box { state = shared; get value() { return this.state; } }
    ${calls}
    const unrelated = 42;
  `);
  expect(ir.coverage).toEqual({ status: "complete", omittedCount: 0 });
  expect(onlyBinding(ir, "unrelated").value).toEqual({
    status: "literal",
    value: 42,
  });
});
