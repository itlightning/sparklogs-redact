export { RedactUploadWizard } from "./RedactUploadWizard.tsx";
export type {
  RedactUploadWizardProps,
  UploadPayload,
  UploadFile,
  UploadContext,
  FormFields,
  ConsentItem,
  ConsentGroupsConfig,
  NudgeConfig,
  CopyConfig,
  CategoryDisplay,
  ProfileName,
  Detection,
  ClassifyPolicy,
  PreviewRenderArgs,
} from "./types.ts";
export {
  DEFAULT_CATEGORY_META,
  DEFAULT_REDACTION_RULES,
  LOCKED_CATEGORIES,
} from "./categoryMeta.ts";
export { classifyFile, DEFAULT_IMAGE_EXTS, DEFAULT_DOC_EXTS } from "./classify.ts";
export { runRedaction, buildSegments } from "./redaction.ts";
export type { RedactionSummary, Segment, UsageEntry, FileRedaction } from "./redaction.ts";
