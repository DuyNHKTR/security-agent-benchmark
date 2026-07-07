/**
 * Locale string tables for the detection report. Both languages render through
 * the same template in score.ts, so every user-visible string lives here.
 * Cell state labels (exact / ≈fuzzy / loc-only / miss / no run) stay in English
 * in both locales: they are the benchmark's state vocabulary and must match the
 * values in detection.json / detection.csv — the legend translates their meaning.
 */
export type ReportLang = "en" | "vi";

export interface ReportStrings {
  docTitle: string;
  reportTitle: string;
  reportSubtitle: string;
  metaLine: string;
  spanCapOff: string;

  tileDetected: string;
  tileCi: string;
  tileStrict: string;
  tileDiscrimination: string;
  tileOnTarget: string;

  recallHeading: string;
  barDetail: string;

  matrixHeading: string;
  legendExact: string;
  legendFuzzy: string;
  legendLocOnly: string;
  legendMiss: string;
  legendNoRun: string;
  legendDagger: string;
  thCase: string;
  thDifficulty: string;
  thCwe: string;
  cellNoRun: string;
  cellLocOnly: string;
  cellMiss: string;
  cellExact: string;
  cellFuzzy: string;
  titleContamination: string;
  titleLocOnly: string;
  titleMiss: string;
  titleMissOversized: string;
  titleHit: string;

  summaryHeading: string;
  thModel: string;
  thRecall: string;
  thCi: string;
  thStrict: string;
  thDetected: string;
  thLocOnly: string;
  thExact: string;
  thFuzzy: string;
  thNoRun: string;
  thOnTarget: string;
  thOversized: string;
  thContaminated: string;

  controlsHeading: string;
  thControlRuns: string;
  thConfirmedFp: string;
  thControlFindings: string;
  thDiscrimination: string;
  controlsNote: string;

  calibrationHeading: string;
  thHighConf: string;
  thMediumConf: string;
  thLowConf: string;
  calibrationNote: string;

  pairwiseHeading: string;
  thOnlyA: string;
  thOnlyB: string;
  thBoth: string;
  thNeither: string;
  thPValue: string;
  pairwiseNote: string;

  methodologyNote: string;
}

/** Interpolate {name} placeholders. Missing vars are left visible, not swallowed. */
export function fmt(template: string, vars: Record<string, string | number> = {}): string {
  return template.replace(/\{(\w+)\}/g, (token, name) => (name in vars ? String(vars[name]) : token));
}

const en: ReportStrings = {
  docTitle: "{suite} detection",
  reportTitle: "{suite} — vulnerability detection",
  reportSubtitle: "Model comparison against ground truth derived from security-fix commits",
  metaLine: "Generated {date} · line tolerance ±{tolerance} · location span cap {spanCap} · ground truth from security-fix diffs",
  spanCapOff: "off",

  tileDetected: "{detected}/{expected} detected",
  tileCi: "95% CI {ci}",
  tileStrict: "Strict recall",
  tileDiscrimination: "Discrimination",
  tileOnTarget: "On-target findings",

  recallHeading: "Recall — share of known vulnerabilities each model detected",
  barDetail: "({detected}/{expected} · 95% CI {ci})",

  matrixHeading: "Detection matrix",
  legendExact: "exact — flagged the fixed line",
  legendFuzzy: "fuzzy — within ±{tolerance} lines",
  legendLocOnly: "loc-only — right lines, wrong CWE",
  legendMiss: "miss — findings, none on target",
  legendNoRun: "no run — refused/incomplete/absent",
  legendDagger: "† — fix predates model's training cutoff",
  thCase: "Vulnerability (case)",
  thDifficulty: "Diff.",
  thCwe: "CWE",
  cellNoRun: "no run",
  cellLocOnly: "loc-only",
  cellMiss: "miss",
  cellExact: "exact",
  cellFuzzy: "≈fuzzy",
  titleContamination: "fix predates this model's training cutoff — memorization possible",
  titleLocOnly: "right location, CWE mismatch ({findings} findings)",
  titleMiss: "{findings} findings, none on target",
  titleMissOversized: "; {oversized} oversized-only overlap(s) discarded",
  titleHit: "{matched}/{total} regions",

  summaryHeading: "Summary",
  thModel: "Model",
  thRecall: "Recall",
  thCi: "95% CI",
  thStrict: "Strict recall",
  thDetected: "Detected",
  thLocOnly: "Loc-only",
  thExact: "Exact",
  thFuzzy: "Fuzzy",
  thNoRun: "No run",
  thOnTarget: "On-target findings",
  thOversized: "Oversized-only",
  thContaminated: "Contam. cases",

  controlsHeading: "Negative controls — scans of the patched commit",
  thControlRuns: "Control runs",
  thConfirmedFp: "Confirmed false positives",
  thControlFindings: "Control findings",
  thDiscrimination: "Discrimination",
  controlsNote: "A confirmed false positive is a finding placed on the patched region while scanning the fixed commit — the bug is provably gone there. Discrimination = cases where the model flagged the vulnerable commit and stayed clean at the patched site on the fixed commit; flagging both suggests pattern-matching or memorization rather than analysis.",

  calibrationHeading: "Confidence calibration — on-target rate by model-reported confidence",
  thHighConf: "High conf.",
  thMediumConf: "Medium conf.",
  thLowConf: "Low conf.",
  calibrationNote: "A well-calibrated model's high-confidence findings hit known vulnerabilities more often than its low-confidence ones. Off-target findings may still be real bugs outside the seeded set, so read rates as directional.",

  pairwiseHeading: "Pairwise comparison (exact McNemar, paired by case)",
  thOnlyA: "Only A",
  thOnlyB: "Only B",
  thBoth: "Both",
  thNeither: "Neither",
  thPValue: "p-value",
  pairwiseNote: "Same cases, paired outcomes; refusals count as not-detected. p ≥ 0.05 means the suite cannot distinguish the two models — add cases before reading a ranking from the bars above.",

  methodologyNote: "Detected = a span-capped finding location overlaps the fix-diff lines and (when the case sets an expected CWE) an on-target finding reports a matching CWE. Strict recall counts only tolerance-0 localizations. \"On-target findings\" is a directional precision signal, not a false-positive rate — confirmed false positives come from the negative-control runs."
};

const vi: ReportStrings = {
  docTitle: "{suite} — báo cáo phát hiện",
  reportTitle: "{suite} — phát hiện lỗ hổng bảo mật",
  reportSubtitle: "So sánh các mô hình trên đáp án chuẩn rút ra từ các commit vá lỗi bảo mật",
  metaLine: "Tạo lúc {date} · dung sai dòng ±{tolerance} · giới hạn tổng số dòng mỗi phát hiện: {spanCap} · đáp án chuẩn lấy từ diff của commit vá lỗi",
  spanCapOff: "tắt",

  tileDetected: "phát hiện {detected}/{expected}",
  tileCi: "khoảng tin cậy 95%: {ci}",
  tileStrict: "Strict recall",
  tileDiscrimination: "Phân biệt (discrimination)",
  tileOnTarget: "Phát hiện trúng mục tiêu",

  recallHeading: "Recall — tỷ lệ lỗ hổng đã biết mà mỗi mô hình phát hiện được",
  barDetail: "({detected}/{expected} · CI 95% {ci})",

  matrixHeading: "Ma trận phát hiện",
  legendExact: "exact — chỉ đúng dòng đã được vá",
  legendFuzzy: "fuzzy — trong phạm vi ±{tolerance} dòng",
  legendLocOnly: "loc-only — đúng vị trí nhưng sai CWE",
  legendMiss: "miss — có phát hiện nhưng không trúng mục tiêu",
  legendNoRun: "no run — từ chối / chưa hoàn tất / không có lượt chạy",
  legendDagger: "† — bản vá có trước mốc dữ liệu huấn luyện của mô hình",
  thCase: "Lỗ hổng (case)",
  thDifficulty: "Độ khó",
  thCwe: "CWE",
  cellNoRun: "no run",
  cellLocOnly: "loc-only",
  cellMiss: "miss",
  cellExact: "exact",
  cellFuzzy: "≈fuzzy",
  titleContamination: "bản vá có trước mốc dữ liệu huấn luyện của mô hình — có thể do ghi nhớ",
  titleLocOnly: "đúng vị trí, sai CWE ({findings} phát hiện)",
  titleMiss: "{findings} phát hiện, không có phát hiện nào trúng mục tiêu",
  titleMissOversized: "; {oversized} phát hiện chỉ trùng khi vượt giới hạn độ dài — đã loại",
  titleHit: "{matched}/{total} vùng",

  summaryHeading: "Tổng hợp",
  thModel: "Mô hình",
  thRecall: "Recall",
  thCi: "CI 95%",
  thStrict: "Strict recall",
  thDetected: "Đã phát hiện",
  thLocOnly: "Loc-only",
  thExact: "Exact",
  thFuzzy: "Fuzzy",
  thNoRun: "No run",
  thOnTarget: "Trúng mục tiêu",
  thOversized: "Chỉ vượt giới hạn",
  thContaminated: "Ca nghi nhiễm",

  controlsHeading: "Đối chứng âm — quét commit đã vá",
  thControlRuns: "Lượt đối chứng",
  thConfirmedFp: "Dương tính giả đã xác nhận",
  thControlFindings: "Phát hiện trên bản vá",
  thDiscrimination: "Phân biệt",
  controlsNote: "Dương tính giả đã xác nhận là phát hiện đặt lên vùng đã vá khi quét commit đã sửa — git chứng minh lỗi không còn ở đó. Phân biệt (discrimination) = số ca mà mô hình vừa cảnh báo trên commit chứa lỗi vừa giữ sạch tại vị trí đã vá trên commit đã sửa; cảnh báo cả hai cho thấy mô hình khớp mẫu hoặc ghi nhớ thay vì thực sự phân tích.",

  calibrationHeading: "Hiệu chuẩn độ tin cậy — tỷ lệ trúng mục tiêu theo mức tin cậy mô hình tự báo",
  thHighConf: "Tin cậy cao",
  thMediumConf: "Tin cậy trung bình",
  thLowConf: "Tin cậy thấp",
  calibrationNote: "Mô hình hiệu chuẩn tốt có phát hiện độ-tin-cậy-cao trúng lỗ hổng đã biết thường xuyên hơn phát hiện độ-tin-cậy-thấp. Phát hiện ngoài mục tiêu vẫn có thể là lỗi thật ngoài bộ đáp án, nên chỉ đọc các tỷ lệ này theo hướng tham khảo.",

  pairwiseHeading: "So sánh theo cặp (kiểm định McNemar chính xác, ghép theo case)",
  thOnlyA: "Chỉ A",
  thOnlyB: "Chỉ B",
  thBoth: "Cả hai",
  thNeither: "Không bên nào",
  thPValue: "p-value",
  pairwiseNote: "Cùng bộ case, kết quả ghép cặp; lượt từ chối tính là không-phát-hiện. p ≥ 0.05 nghĩa là bộ đánh giá chưa đủ để phân biệt hai mô hình — hãy thêm case trước khi đọc thứ hạng từ biểu đồ phía trên.",

  methodologyNote: "Đã phát hiện = một vị trí phát hiện (trong giới hạn tổng số dòng) trùng với các dòng trong diff vá lỗi và (khi case khai báo CWE kỳ vọng) một phát hiện trúng mục tiêu báo đúng CWE. Strict recall chỉ tính các định vị chính xác tuyệt đối (dung sai 0). \"Trúng mục tiêu\" là tín hiệu định hướng về độ chính xác, không phải tỷ lệ dương tính giả — dương tính giả được xác nhận qua các lượt chạy đối chứng âm."
};

export const locales: Record<ReportLang, ReportStrings> = { en, vi };
export const reportLangs: ReportLang[] = ["en", "vi"];
