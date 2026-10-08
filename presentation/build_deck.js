const pptxgen = require("pptxgenjs");
const React = require("react");
const ReactDOMServer = require("react-dom/server");
const sharp = require("sharp");
const fa = require("react-icons/fa");
const { applyTheme } = require("/home/linuxuser/.claude/skills/synced/fc0dfa8b-b158-4325-847a-65241799bcd2_be856da8-cef2-4dd8-9a1e-af9474281d82/pptx/scripts/apply_theme.js");

const OUT = require("path").join(__dirname, "NetSentinel.pptx");  // run: NODE_PATH=<dir with pptxgenjs etc.>/node_modules node build_deck.js
const THEME = {
  name: "NetSentinel",
  headFontFace: "Cambria",
  bodyFontFace: "Calibri",
  colors: {
    dk1: "0E1726", lt1: "FFFFFF", dk2: "24344D", lt2: "EEF2F7",
    accent1: "E4572E", accent2: "1F9D8B", accent3: "F2B134", accent4: "3E6FB0", accent5: "8A97AB", accent6: "7A4FB5",
    hlink: "3E6FB0", folHlink: "7A4FB5",
  },
};
const HEX = THEME.colors;

async function icon(Comp, color = "FFFFFF") {
  const svg = ReactDOMServer.renderToStaticMarkup(React.createElement(Comp, { color: "#" + color, size: 256 }));
  const buf = await sharp(Buffer.from(svg)).resize(256, 256).png().toBuffer();
  return "image/png;base64," + buf.toString("base64");
}

(async () => {
  const pres = new pptxgen();
  pres.layout = "LAYOUT_WIDE"; // 13.33 x 7.5
  pres.title = "NetSentinel";
  pres.author = "NetSentinel project";
  pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
  const C = pres.SchemeColor;

  // ── layouts ────────────────────────────────────────────────────────────────────────────────────
  pres.defineSlideMaster({
    title: "Title", background: { color: C.text1 },
    objects: [
      { placeholder: { options: { name: "title", type: "title", x: 0.8, y: 2.2, w: 11.7, h: 1.6, fontSize: 48, bold: true, align: "left",
          color: C.background1, valign: "bottom" }, text: "" } },
      { placeholder: { options: { name: "body", type: "body", x: 0.8, y: 4.0, w: 11.0, h: 1.4, fontSize: 20, align: "left",
          color: C.accent5, valign: "top" }, text: "" } },
    ],
  });
  pres.defineSlideMaster({
    title: "Section", background: { color: C.text2 },
    objects: [
      { placeholder: { options: { name: "title", type: "title", x: 0.8, y: 2.6, w: 11.7, h: 1.2, fontSize: 40, bold: true, align: "left",
          color: C.background1, valign: "bottom" }, text: "" } },
      { placeholder: { options: { name: "body", type: "body", x: 0.8, y: 3.9, w: 11.0, h: 1.0, fontSize: 18, align: "left",
          color: C.background2, valign: "top" }, text: "" } },
    ],
    slideNumber: { x: 12.3, y: 6.95, w: 0.6, h: 0.3, fontSize: 10, color: C.accent5, align: "right" },
  });
  pres.defineSlideMaster({
    title: "Content", background: { color: C.background1 },
    margin: [0.5, 0.6, 0.7, 0.6],
    objects: [
      { placeholder: { options: { name: "title", type: "title", x: 0.6, y: 0.35, w: 12.1, h: 0.9, fontSize: 32, bold: true, align: "left",
          color: C.text1, valign: "middle" }, text: "" } },
      { text: { text: "NetSentinel", options: { x: 0.6, y: 6.95, w: 3, h: 0.3, fontSize: 10, color: C.accent5 } } },
    ],
    slideNumber: { x: 12.3, y: 6.95, w: 0.6, h: 0.3, fontSize: 10, color: C.accent5, align: "right" },
  });

  const add = (master, section) => pres.addSlide({ masterName: master, sectionTitle: section });
  const circleIcon = async (slide, Comp, x, y, d, fill, name) => {
    slide.addShape(pres.shapes.OVAL, { x, y, w: d, h: d, fill: { color: fill }, line: { color: fill }, objectName: name + " circle" });
    const pad = d * 0.25;
    slide.addImage({ data: await icon(Comp), x: x + pad, y: y + pad, w: d - 2 * pad, h: d - 2 * pad, objectName: name + " icon" });
  };
  const chartText = { catAxisLabelFontFace: "+mn-lt", valAxisLabelFontFace: "+mn-lt", dataLabelFontFace: "+mn-lt",
    legendFontFace: "+mn-lt", titleFontFace: "+mn-lt", catAxisLabelColor: HEX.dk2, valAxisLabelColor: HEX.accent5,
    dataLabelColor: HEX.dk1, catAxisLabelFontSize: 12, valAxisLabelFontSize: 11, dataLabelFontSize: 11 };

  // ── 1 title ────────────────────────────────────────────────────────────────────────────────────
  pres.addSection({ title: "Overview" });
  let s = add("Title", "Overview");
  s.addText("NetSentinel", { placeholder: "title" });
  s.addText("From a notebook to a live, human-approved detection platform", { placeholder: "body" });
  await circleIcon(s, fa.FaShieldAlt, 0.8, 0.8, 1.0, C.accent1, "logo");
  s.addNotes("NetSentinel started as a Jupyter notebook on CICIDS-2017 and ended as a running platform: ingest API, ML detection, agents, Claude investigations, risk scoring, human-approved responses, tickets and a dashboard.");

  // ── 2 summary ──────────────────────────────────────────────────────────────────────────────────
  s = add("Content", "Overview");
  s.addText("What was built, in four numbers", { placeholder: "title" });
  const stats = [
    ["19/19", "end-to-end checks passed on the live, hardened system", C.accent2],
    ["100%", "recall on never-seen brute-force attacks (48% before v2)", C.accent1],
    ["12", "pipeline steps, from ingest to dashboard, running as 9 services", C.accent4],
    ["145", "automated tests, including security and tamper tests", C.text2],
  ];
  stats.forEach(([n, label, color], i) => {
    const x = 0.6 + i * 3.1;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y: 1.8, w: 2.85, h: 2.9, rectRadius: 0.12, fill: { color: C.background2 },
      line: { color: C.background2 }, objectName: `stat ${i + 1} card` });
    s.addText(n, { x: x + 0.2, y: 2.1, w: 2.45, h: 1.3, fontSize: 44, bold: true, color, fontFace: THEME.headFontFace,
      isTextBox: true, objectName: `stat ${i + 1} value`, fit: "shrink" });
    s.addText(label, { x: x + 0.2, y: 3.5, w: 2.45, h: 1.6, fontSize: 15, color: C.text2, valign: "top", isTextBox: true,
      objectName: `stat ${i + 1} label` });
  });
  s.addText("Machine learning decides; Claude explains; a human approves every action.", { x: 0.6, y: 5.2, w: 12.1, h: 0.6,
    fontSize: 18, italic: true, color: C.text2, isTextBox: true, objectName: "tagline" });
  s.addNotes("Four headline numbers. The design principle: the model makes the detection decision, the LLM only explains with labelled evidence, and nothing is ever executed without a human.");

  // ── 3 section: starting point ─────────────────────────────────────────────────────────────────
  pres.addSection({ title: "Starting point" });
  s = add("Section", "Starting point");
  s.addText("The starting point", { placeholder: "title" });
  s.addText("A notebook whose results looked strong but could not be trusted", { placeholder: "body" });

  // ── 4 notebook issues ──────────────────────────────────────────────────────────────────────────
  s = add("Content", "Starting point");
  s.addText("Five problems behind 96% accuracy", { placeholder: "title" });
  const issues = [
    [fa.FaExclamationTriangle, "Target leakage", "'Attempted Category' was a model input and marks exactly the '… - Attempted' labels"],
    [fa.FaRandom, "Not a time split", "Files loaded alphabetically, so the 'future' test set held attack types absent from training"],
    [fa.FaFingerprint, "Identity, not behaviour", "Source and destination IPs ranked #4 and #7: the model memorised the lab's addresses"],
    [fa.FaChartLine, "Wrong ROC-AUC", "Computed from 0/1 predictions for two models: balanced accuracy reported as AUC"],
    [fa.FaToggleOn, "Binary only", "Attack / not attack, with no family or type for triage"],
  ];
  for (const [i, [Ic, head, body]] of issues.entries()) {
    const y = 1.55 + i * 1.02;
    await circleIcon(s, Ic, 0.7, y, 0.7, C.accent1, `issue ${i + 1}`);
    s.addText(head, { x: 1.65, y: y - 0.05, w: 4.0, h: 0.45, fontSize: 18, bold: true, color: C.text1, margin: 0,
      isTextBox: true, objectName: `issue ${i + 1} head` });
    s.addText(body, { x: 1.65, y: y + 0.38, w: 10.9, h: 0.45, fontSize: 15, color: C.text2, margin: 0, isTextBox: true,
      objectName: `issue ${i + 1} body` });
  }
  s.addNotes("Each issue was verified on the data, not assumed. The leakage check: every row with Attempted Category other than -1 has an '- Attempted' label.");

  // ── 5 reproducibility chart ────────────────────────────────────────────────────────────────────
  s = add("Content", "Starting point");
  s.addText("Same code and seed, three different answers", { placeholder: "title" });
  s.addChart(pres.charts.BAR, [{ name: "Attack recall", labels: ["Notebook (Colab)", "scikit-learn 1.6.1", "scikit-learn 1.9.1"],
    values: [0.865, 0.580, 0.479] }], {
    x: 0.6, y: 1.5, w: 7.6, h: 4.9, barDir: "bar", chartColors: [HEX.accent4], showValue: true, dataLabelPosition: "outEnd",
    dataLabelFormatCode: "0%", valAxisLabelFormatCode: "0%", valAxisMaxVal: 1, valAxisMinVal: 0, catAxisOrientation: "maxMin",
    valGridLine: { color: "DDE3EC", size: 0.5 }, catGridLine: { style: "none" }, showLegend: false,
    showTitle: true, title: "Random Forest recall on the notebook's test split", titleFontSize: 14, titleColor: HEX.dk2,
    ...chartText, objectName: "RF recall chart" });
  s.addText([
    { text: "The data pipeline reproduced exactly", options: { bold: true, breakLine: true } },
    { text: "3,167 duplicates, 27 dropped features, 1,467,762 / 629,042 rows: identical.", options: { breakLine: true } },
    { text: " ", options: { breakLine: true } },
    { text: "The headline model did not", options: { bold: true, breakLine: true } },
    { text: "Its test attacks were never seen in training, so catching them depended on incidental tree splits." },
  ], { x: 8.6, y: 1.7, w: 4.1, h: 4.5, fontSize: 15, color: C.text2, valign: "top", isTextBox: true, objectName: "repro commentary" });
  s.addNotes("v0 replays the notebook from raw CSVs. Isolation Forest reproduced cell-for-cell; Random Forest swung from 87% to 48% recall across library versions with the same seed.");

  // ── 6 section: model ───────────────────────────────────────────────────────────────────────────
  pres.addSection({ title: "Detection model" });
  s = add("Section", "Detection model");
  s.addText("The detection model", { placeholder: "title" });
  s.addText("v1: a clean feature set and a hierarchy · v2: each source's last 60 seconds", { placeholder: "body" });

  // ── 7 hierarchy ────────────────────────────────────────────────────────────────────────────────
  s = add("Content", "Detection model");
  s.addText("Three questions, and only the first one decides", { placeholder: "title" });
  const stages = [
    ["1", "Normal or attack?", "Decides. Threshold tuned to 0.1% false alerts", C.accent1],
    ["2", "Which family?", "Answers only at ≥ 60% confidence, else 'unknown'", C.accent4],
    ["3", "Which attack type?", "Answers only at ≥ 80% confidence", C.accent2],
  ];
  stages.forEach(([n, head, body, col], i) => {
    const x = 0.6 + i * 4.15;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y: 1.7, w: 3.75, h: 2.6, rectRadius: 0.12, fill: { color: C.background2 },
      line: { color: C.background2 }, objectName: `stage ${n} card` });
    s.addShape(pres.shapes.OVAL, { x: x + 0.3, y: 1.95, w: 0.7, h: 0.7, fill: { color: col }, line: { color: col }, objectName: `stage ${n} badge` });
    s.addText(n, { x: x + 0.3, y: 1.95, w: 0.7, h: 0.7, fontSize: 22, bold: true, color: C.background1, align: "center",
      valign: "middle", margin: 0, isTextBox: true, objectName: `stage ${n} number` });
    s.addText(head, { x: x + 0.3, y: 2.8, w: 3.2, h: 0.5, fontSize: 20, bold: true, color: C.text1, margin: 0, isTextBox: true,
      objectName: `stage ${n} head` });
    s.addText(body, { x: x + 0.3, y: 3.35, w: 3.2, h: 0.8, fontSize: 15, color: C.text2, margin: 0, valign: "top",
      isTextBox: true, objectName: `stage ${n} body` });
    if (i < 2) s.addShape(pres.shapes.RIGHT_ARROW, { x: x + 3.8, y: 2.8, w: 0.3, h: 0.4, fill: { color: C.accent5 },
      line: { color: C.accent5 }, objectName: `stage arrow ${i + 1}` });
  });
  s.addText([
    { text: "Clean inputs: ", options: { bold: true } },
    { text: "83 fixed features (no leakage, no IPs or ports-as-identity) · missing values kept, not dropped · real duplicates removed (259k, not 3k)", options: { breakLine: true } },
    { text: "Attack types seen in training: ", options: { bold: true } },
    { text: "99.999% recall at 0.09% false alerts. Treat as a ceiling: CICIDS-2017 is easy when tools repeat." },
  ], { x: 0.6, y: 4.7, w: 12.1, h: 1.9, fontSize: 15, color: C.text2, valign: "top", paraSpaceAfter: 6, isTextBox: true,
    objectName: "v1 notes" });
  s.addNotes("Stages 2 and 3 never change stage 1's decision; a flow the family model can't name is still an attack.");

  // ── 8 E2 chart ─────────────────────────────────────────────────────────────────────────────────
  s = add("Content", "Detection model");
  s.addText("Window features close the unseen-attack gaps", { placeholder: "title" });
  const fams = ["BruteForce", "Botnet", "PortScan", "WebAttack", "DoS", "DDoS"];
  s.addChart(pres.charts.BAR, [
    { name: "Per-flow features", labels: fams, values: [0.480, 0.807, 0.831, 0.903, 0.927, 1.0] },
    { name: "+ 60 s source window (v2)", labels: fams, values: [1.0, 0.963, 0.921, 1.0, 0.990, 1.0] },
  ], { x: 0.6, y: 1.45, w: 8.4, h: 5.2, barDir: "bar", barGrouping: "clustered", chartColors: [HEX.accent5, HEX.accent2],
    showValue: true, dataLabelPosition: "outEnd", dataLabelFormatCode: "0%", valAxisLabelFormatCode: "0%",
    valAxisMaxVal: 1.1, valAxisMinVal: 0, valAxisMajorUnit: 0.25, catAxisOrientation: "maxMin",
    valGridLine: { color: "DDE3EC", size: 0.5 }, catGridLine: { style: "none" }, showLegend: true, legendPos: "t",
    legendFontSize: 12, legendColor: HEX.dk2, showTitle: false, ...chartText, objectName: "E2 comparison chart" });
  s.addText([
    { text: "How it was tested", options: { bold: true, breakLine: true } },
    { text: "Each family is removed from training, then tested at the same 0.1% false-alert budget.", options: { breakLine: true } },
    { text: " ", options: { breakLine: true } },
    { text: "Why it works", options: { bold: true, breakLine: true } },
    { text: "A scan probe looks like a handshake; 997 ports in a minute does not. Features are causal: only flows already ended count." },
  ], { x: 9.3, y: 1.6, w: 3.4, h: 4.9, fontSize: 15, color: C.text2, valign: "top", isTextBox: true, objectName: "E2 commentary" });
  s.addNotes("Both detectors were trained on the same rows and splits; only the window features differ. v2 needed the authors' corrected CICIDS-2017 with full timestamps, because the Kaggle copy lost the hour.");

  // ── 9 live replay table ────────────────────────────────────────────────────────────────────────
  s = add("Content", "Detection model");
  s.addText("v2 caught every attack in real replayed traffic", { placeholder: "title" });
  const hdr = (t) => ({ text: t, options: { bold: true, color: C.background1, fill: { color: C.text2 } } });
  s.addTable([
    [hdr("Real traffic slice"), hdr("Attacks caught"), hdr("Family correct"), hdr("False alarms")],
    ["Port scan (Fri, 1 min)", "997 / 997", "100%", "0 / 279"],
    ["FTP brute force (Tue, 2 min)", "124 / 124", "100%", "2 / 1,816"],
    ["SSH brute force (Tue, 2 min)", "102 / 102", "100%", "6 / 1,318"],
    ["Botnet attempts (Fri, 3 min)", "42 / 42", "100%", "6 / 1,645"],
  ], { x: 0.6, y: 1.6, w: 8.2, colW: [3.4, 1.55, 1.55, 1.7], fontSize: 15, color: C.text1, border: { type: "solid", color: "DDE3EC", pt: 0.75 },
    rowH: 0.62, valign: "middle", objectName: "live replay table" });
  [["1,265 / 1,265", "attack flows caught", C.accent2], ["0.28%", "false alarms on 5,058 benign flows", C.accent1]].forEach(([n, l, col], i) => {
    const x = 0.6 + i * 4.2;
    s.addText(n, { x, y: 5.0, w: 4.0, h: 0.8, fontSize: 36, bold: true, color: col, fontFace: THEME.headFontFace, margin: 0,
      isTextBox: true, objectName: `replay stat ${i + 1} value` });
    s.addText(l, { x, y: 5.8, w: 4.0, h: 0.4, fontSize: 14, color: C.text2, margin: 0, isTextBox: true, objectName: `replay stat ${i + 1} label` });
  });
  await circleIcon(s, fa.FaClipboardCheck, 9.4, 1.65, 0.75, C.accent2, "replay check");
  s.addText([
    { text: "Every attack flow caught and named", options: { bold: true, breakLine: true } },
    { text: "False alarms ran higher than the 0.10% seen in validation; all scored just above v2's very low threshold." },
  ], { x: 9.4, y: 2.6, w: 3.3, h: 3.6, fontSize: 15, color: C.text2, valign: "top", isTextBox: true, objectName: "replay commentary" });
  s.addNotes("Replays send flows in the order they ended, with a 60-second warm-up and no overlap between replays; live window values were checked equal to training values.");

  // ── 10 section: platform ───────────────────────────────────────────────────────────────────────
  pres.addSection({ title: "Platform" });
  s = add("Section", "Platform");
  s.addText("The platform", { placeholder: "title" });
  s.addText("Twelve steps, six agents, one human in control", { placeholder: "body" });

  // ── 11 pipeline ────────────────────────────────────────────────────────────────────────────────
  s = add("Content", "Platform");
  s.addText("From a network flow to a ticket in one pipeline", { placeholder: "title" });
  const steps = [
    [fa.FaSatelliteDish, "Ingest", "API key, validation", C.accent4],
    [fa.FaFilter, "Detect", "Model Check, v2 model", C.accent1],
    [fa.FaProjectDiagram, "Correlate", "cases by source", C.text2],
    [fa.FaRobot, "Investigate", "Claude, guarded", C.accent6],
    [fa.FaBalanceScale, "Score risk", "explainable rules", C.accent3],
    [fa.FaUserShield, "Propose", "reversible only", C.accent2],
    [fa.FaTicketAlt, "Ticket", "SLA, timeline", C.accent4],
  ];
  for (const [i, [Ic, head, body, col]] of steps.entries()) {
    const x = 0.6 + i * 1.75;
    await circleIcon(s, Ic, x + 0.38, 1.6, 0.85, col, `step ${i + 1}`);
    s.addText(head, { x, y: 2.55, w: 1.6, h: 0.4, fontSize: 16, bold: true, color: C.text1, align: "center", margin: 0,
      isTextBox: true, objectName: `step ${i + 1} head` });
    s.addText(body, { x, y: 2.95, w: 1.6, h: 0.5, fontSize: 12, color: C.text2, align: "center", margin: 0, valign: "top",
      isTextBox: true, objectName: `step ${i + 1} body` });
  }
  s.addImage({ path: require("path").join(__dirname, "dash.png"), x: 0.6, y: 3.7, w: 4.8, h: 2.9, objectName: "dashboard screenshot", sizing: { type: "cover", w: 4.8, h: 2.9 } });
  s.addText([
    { text: "Every investigation keeps four labelled sections", options: { bold: true, breakLine: true } },
    { text: "VERIFIED TELEMETRY · MODEL OUTPUT · LLM ANALYSIS · RECOMMENDATION", options: { color: C.accent1, bold: true, breakLine: true } },
    { text: " ", options: { breakLine: true } },
    { text: "Claude cannot change a detection or a risk score. A guard rejects any analysis naming an IP that is not in the evidence, and strips containment steps from its advice." },
  ], { x: 5.8, y: 3.75, w: 6.9, h: 2.8, fontSize: 15, color: C.text2, valign: "top", isTextBox: true, objectName: "pipeline commentary" });
  s.addNotes("Agents talk through a Postgres event bus with at-least-once delivery. The dashboard screenshot is the live read-only view.");

  // ── 12 human in control + security ─────────────────────────────────────────────────────────────
  s = add("Content", "Platform");
  s.addText("A human approves; secrets stay out of code", { placeholder: "title" });
  const cards = [
    [fa.FaUserCheck, "Human approval", "Response actions are a closed list of reversible steps. The database refuses any decision by an agent; dashboard decisions re-ask for your key.", C.accent2],
    [fa.FaKey, "Secrets in OpenBao", "Database password rotates daily through the Security Wall. API keys are stored only as hashes; you created yours on your own PC.", C.accent4],
    [fa.FaLock, "Hardened services", "Sandbox score 8.5 → 1.6 (systemd). HTTPS with Let's Encrypt, dashboard limited to your IPs, model files hash-checked before loading.", C.accent1],
  ];
  for (const [i, [Ic, head, body, col]] of cards.entries()) {
    const x = 0.6 + i * 4.15;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y: 1.6, w: 3.85, h: 3.9, rectRadius: 0.12, fill: { color: C.background2 },
      line: { color: C.background2 }, objectName: `control ${i + 1} card` });
    await circleIcon(s, Ic, x + 0.35, 1.9, 0.85, col, `control ${i + 1}`);
    s.addText(head, { x: x + 0.35, y: 2.95, w: 3.2, h: 0.5, fontSize: 20, bold: true, color: C.text1, margin: 0,
      isTextBox: true, objectName: `control ${i + 1} head` });
    s.addText(body, { x: x + 0.35, y: 3.5, w: 3.2, h: 2.5, fontSize: 15, color: C.text2, margin: 0, valign: "top",
      isTextBox: true, objectName: `control ${i + 1} body` });
  }
  s.addNotes("Security review: no secrets in git or logs, least-privilege database role, append-only audit tables, no known dependency vulnerabilities.");

  // ── 13 live sensor ─────────────────────────────────────────────────────────────────────────────
  pres.addSection({ title: "Live traffic" });
  s = add("Content", "Live traffic");
  s.addText("Live traffic: ranking holds, thresholds don't", { placeholder: "title" });
  s.addChart(pres.charts.BAR, [
    { name: "Scan flows caught", labels: ["10% false alarms", "5% false alarms", "2% false alarms"], values: [0.90, 0.85, 0.02] },
    { name: "SSH-guessing flows caught", labels: ["10% false alarms", "5% false alarms", "2% false alarms"], values: [1.0, 1.0, 0.29] },
  ], { x: 0.6, y: 1.45, w: 7.4, h: 5.1, barDir: "col", barGrouping: "clustered", chartColors: [HEX.accent1, HEX.accent4],
    showValue: true, dataLabelPosition: "outEnd", dataLabelFormatCode: "0%", valAxisLabelFormatCode: "0%",
    valAxisMaxVal: 1.1, valAxisMinVal: 0, valAxisMajorUnit: 0.25, valGridLine: { color: "DDE3EC", size: 0.5 },
    catGridLine: { style: "none" }, showLegend: true, legendPos: "t", legendFontSize: 12, legendColor: HEX.dk2,
    showTitle: false, ...chartText, objectName: "live operating curve chart" });
  s.addText([
    { text: "Labels from the server's own logs", options: { bold: true, breakLine: true } },
    { text: "Firewall blocks mark scanners; failed SSH logins mark password guessing. ROC-AUC 0.95.", options: { breakLine: true } },
    { text: " ", options: { breakLine: true } },
    { text: "Decision: alerts stay off", options: { bold: true, breakLine: true } },
    { text: "The sensor runs in shadow mode (scored, no tickets) until calibrated on a day of data." },
  ], { x: 8.4, y: 1.6, w: 4.3, h: 4.9, fontSize: 15, color: C.text2, valign: "top", isTextBox: true, objectName: "live commentary" });
  s.addNotes("A first alert-mode run flagged 55% of flows, including the server's own HTTPS and its Claude API calls; those 75 cases were closed and shadow mode added. The flow meter needed four fixes to match training: microseconds, exact timestamps, a double-counted first packet, and a 240-second export delay.");

  // ── 14 next steps (dark) ───────────────────────────────────────────────────────────────────────
  s = add("Title", "Live traffic");
  s.addText("Next steps", { placeholder: "title" });
  s.addText([
    { text: "Calibrate on 24 h of live traffic (netsentinel calibrate)", options: { bullet: true, breakLine: true, color: C.background2 } },
    { text: "Retrain on features from the same flow meter as the sensor", options: { bullet: true, breakLine: true, color: C.background2 } },
    { text: "Approve a per-source alert threshold, then switch the sensor to --alert", options: { bullet: true, color: C.background2 } },
  ], { placeholder: "body" });
  s.addNotes("Everything else is live, tested and documented in the repository (README, docs/, presentation notebook).");

  await pres.writeFile({ fileName: OUT });
  await applyTheme(OUT, THEME);
  console.log("wrote", OUT);
})().catch((e) => { console.error(e); process.exit(1); });
