import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import { CdpCaptureCompleteness } from "./CdpCaptureCompleteness.js";
import {
  captureDom,
  captureFrames,
  captureResources,
  type ElectronContext,
} from "./CdpElectronInspection.js";
import type { CdpConnection } from "./CdpConnection.js";

const temporary: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporary
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

const localRoot = async (): Promise<string> => {
  const root = await mkdtemp(join(tmpdir(), "rea-electron-content-"));
  temporary.push(root);
  return root;
};

/** A connection that answers each named command from a fixed script. */
const scriptedConnection = (
  answers: Readonly<Record<string, unknown>>,
): CdpConnection =>
  ({
    async send(method: string) {
      if (!Object.hasOwn(answers, method))
        throw new Error(`unexpected command: ${method}`);
      return answers[method];
    },
  }) as unknown as CdpConnection;

const electronContext = (
  connection: CdpConnection,
  root: string,
): ElectronContext =>
  ({
    connection,
    sessionId: undefined,
    discovery: {} as never,
    target: { id: "target-page" } as never,
    input: { cdp_endpoint: "", target_id: "" } as never,
  }) as unknown as ElectronContext;

const pageUrl = (root: string, name = "index.html"): string =>
  pathToFileURL(join(root, name)).href;

const resourceTree = (
  root: string,
  frameResources: unknown,
  childFrames: unknown = [],
): Record<string, unknown> => ({
  frameTree: {
    frame: { id: "frame-main", url: pageUrl(root) },
    resources: frameResources,
    childFrames,
  },
});

describe("Electron resource inventory admission", () => {
  it("retains one authorized resource beside an empty sibling inventory", async () => {
    const root = await localRoot();
    await writeFile(join(root, "app.js"), "script");
    const completeness = new CdpCaptureCompleteness();

    const resources = await captureResources(
      electronContext(
        scriptedConnection({
          "Page.getResourceTree": resourceTree(root, [
            {
              url: pageUrl(root, "app.js"),
              type: "Script",
              mimeType: "text/javascript",
              contentSize: 6,
            },
          ]),
        }),
        root,
      ),
      completeness,
    );

    expect(resources).toHaveLength(1);
    expect(resources[0]?.file_path).toContain("app.js");
    expect(completeness.snapshot()).toMatchObject({
      status: "complete_within_window",
      unavailable_sections: [],
      excluded: [],
    });
  });

  it("reports a frame whose resource inventory is missing rather than empty", async () => {
    const root = await localRoot();
    const completeness = new CdpCaptureCompleteness();

    const resources = await captureResources(
      electronContext(
        scriptedConnection({
          "Page.getResourceTree": resourceTree(root, undefined),
        }),
        root,
      ),
      completeness,
    );

    expect(resources).toEqual([]);
    expect(completeness.snapshot()).toMatchObject({
      unavailable_sections: ["resources"],
      excluded: [
        { section: "resources", reason: "invalid_protocol_value", count: null },
      ],
    });
    expect(completeness.snapshot().conditions).toContain("attach_limited");
  });

  it("reports a non-array resource inventory rather than empty", async () => {
    const root = await localRoot();
    const completeness = new CdpCaptureCompleteness();

    const resources = await captureResources(
      electronContext(
        scriptedConnection({
          "Page.getResourceTree": resourceTree(root, { not: "an array" }),
        }),
        root,
      ),
      completeness,
    );

    expect(resources).toEqual([]);
    expect(completeness.snapshot().unavailable_sections).toContain("resources");
  });

  it("counts each malformed resource entry instead of dropping it silently", async () => {
    const root = await localRoot();
    await writeFile(join(root, "app.js"), "script");
    const completeness = new CdpCaptureCompleteness();

    const resources = await captureResources(
      electronContext(
        scriptedConnection({
          "Page.getResourceTree": resourceTree(root, [
            null,
            {
              url: pageUrl(root, "app.js"),
              type: "Script",
              mimeType: "text/javascript",
              contentSize: 6,
            },
            "not-a-record",
          ]),
        }),
        root,
      ),
      completeness,
    );

    expect(resources).toHaveLength(1);
    expect(completeness.snapshot().excluded).toContainEqual({
      section: "resources",
      reason: "invalid_protocol_value",
      count: 2,
    });
  });
});

describe("Electron resource entry accounting", () => {
  it("reports a malformed child frame subtree rather than dropping it", async () => {
    const root = await localRoot();
    const completeness = new CdpCaptureCompleteness();

    const resources = await captureResources(
      electronContext(
        scriptedConnection({
          "Page.getResourceTree": resourceTree(
            root,
            [],
            [
              {
                frame: { id: "frame-child", url: pageUrl(root) },
                childFrames: "not-an-array",
              },
            ],
          ),
        }),
        root,
      ),
      completeness,
    );

    expect(resources).toEqual([]);
    expect(completeness.snapshot().unavailable_sections).toContain("resources");
  });

  it("keeps a child frame's authorized resources after its parent answered", async () => {
    const root = await localRoot();
    await writeFile(join(root, "child.js"), "script");
    const completeness = new CdpCaptureCompleteness();

    const resources = await captureResources(
      electronContext(
        scriptedConnection({
          "Page.getResourceTree": resourceTree(
            root,
            [],
            [
              {
                frame: { id: "frame-child", url: pageUrl(root) },
                resources: [
                  {
                    url: pageUrl(root, "child.js"),
                    type: "Script",
                    mimeType: "text/javascript",
                    contentSize: 6,
                  },
                ],
                childFrames: [
                  {
                    frame: { id: "frame-grandchild", url: pageUrl(root) },
                    resources: "not-an-array",
                  },
                ],
              },
            ],
          ),
        }),
        root,
      ),
      completeness,
    );

    expect(resources).toHaveLength(1);
    expect(resources[0]?.file_path).toContain("child.js");
    expect(completeness.snapshot().unavailable_sections).toContain("resources");
  });
});

describe("Electron DOM capture", () => {
  const snapshot = (
    strings: unknown,
    documents: unknown,
  ): Record<string, unknown> => ({ strings, documents });

  it("projects a complete snapshot", async () => {
    const root = await localRoot();
    await writeFile(join(root, "index.html"), "page");
    const completeness = new CdpCaptureCompleteness();

    const dom = await captureDom(
      electronContext(
        scriptedConnection({
          "DOMSnapshot.captureSnapshot": snapshot(
            [pageUrl(root), "button"],
            [
              {
                documentURL: 0,
                nodes: {
                  nodeType: [1, 1],
                  nodeName: [1, 1],
                  nodeValue: [0, 0],
                  parentIndex: [-1, 0],
                  attributes: [[], ["id", 0]],
                },
              },
            ],
          ),
        }),
        root,
      ),
      completeness,
    );

    expect(dom.total_nodes).toBe(2);
    expect(dom.nodes.map((node) => node.node_name)).toEqual([
      "button",
      "button",
    ]);
    expect(completeness.snapshot()).toMatchObject({
      status: "complete_within_window",
      unavailable_sections: [],
    });
  });

  it("reports a snapshot without its string table rather than empty names", async () => {
    const root = await localRoot();
    await writeFile(join(root, "index.html"), "page");
    const completeness = new CdpCaptureCompleteness();

    const dom = await captureDom(
      electronContext(
        scriptedConnection({
          "DOMSnapshot.captureSnapshot": snapshot(undefined, [
            {
              documentURL: 0,
              nodes: {
                nodeType: [1],
                nodeName: [1],
                nodeValue: [0],
                parentIndex: [-1],
                attributes: [[]],
              },
            },
          ]),
        }),
        root,
      ),
      completeness,
    );

    expect(dom).toEqual({ total_nodes: 0, nodes: [] });
    expect(dom.nodes).toEqual([]);
    expect(completeness.snapshot().unavailable_sections).toContain("dom");
    expect(completeness.snapshot().excluded).toContainEqual({
      section: "dom",
      reason: "invalid_protocol_value",
      count: null,
    });
    // A missing string table must not be misattributed as an authorization
    // decision: the document URL index cannot resolve at all.
    expect(completeness.snapshot().excluded).not.toContainEqual({
      section: "dom",
      reason: "out_of_target_scope",
      count: 1,
    });
  });

  it("reports a snapshot whose documents field is not an array", async () => {
    const root = await localRoot();
    const completeness = new CdpCaptureCompleteness();

    const dom = await captureDom(
      electronContext(
        scriptedConnection({
          "DOMSnapshot.captureSnapshot": snapshot([pageUrl(root)], {
            documents: true,
          }),
        }),
        root,
      ),
      completeness,
    );

    expect(dom).toEqual({ total_nodes: 0, nodes: [] });
    expect(completeness.snapshot().unavailable_sections).toContain("dom");
  });

  it("counts each malformed document entry instead of dropping it silently", async () => {
    const root = await localRoot();
    await writeFile(join(root, "index.html"), "page");
    const completeness = new CdpCaptureCompleteness();

    const dom = await captureDom(
      electronContext(
        scriptedConnection({
          "DOMSnapshot.captureSnapshot": snapshot(
            [pageUrl(root)],
            [
              null,
              {
                documentURL: 0,
                nodes: {
                  nodeType: [1],
                  nodeName: [0],
                  nodeValue: [0],
                  parentIndex: [-1],
                  attributes: [[]],
                },
              },
              "not-a-record",
            ],
          ),
        }),
        root,
      ),
      completeness,
    );

    expect(dom.total_nodes).toBe(1);
    expect(completeness.snapshot().excluded).toContainEqual({
      section: "dom",
      reason: "invalid_protocol_value",
      count: 2,
    });
  });
});
