// Icon path data is from Lucide (https://lucide.dev), ISC licensed — see THIRD-PARTY-NOTICES.md.
// Inlined as small SVG components (not an icon dependency) so the package pulls in no icon runtime.
// Each icon is a function component taking standard SVG props (stroke 2, round caps).
import type { SVGProps } from "react";

type IconProps = SVGProps<SVGSVGElement>;

function svg(children: React.ReactNode) {
  return function Icon(props: IconProps) {
    return (
      <svg
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth={2}
        strokeLinecap="round"
        strokeLinejoin="round"
        xmlns="http://www.w3.org/2000/svg"
        aria-hidden="true"
        {...props}
      >
        {children}
      </svg>
    );
  };
}

export const UploadCloud = svg(
  <>
    <path d="M12 13v8" />
    <path d="m8 17 4-4 4 4" />
    <path d="M20 16.2A4.5 4.5 0 0 0 17.5 8h-1.8A7 7 0 1 0 4 14.9" />
  </>,
);
export const Folder = svg(
  <path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z" />,
);
export const FileText = svg(
  <>
    <path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z" />
    <path d="M14 2v5h5" />
    <line x1={9} y1={13} x2={15} y2={13} />
    <line x1={9} y1={17} x2={13} y2={17} />
  </>,
);
export const File = svg(
  <>
    <path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z" />
    <path d="M14 2v5h5" />
  </>,
);
export const FileQuestion = svg(
  <>
    <path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z" />
    <path d="M14 2v5h5" />
    <path d="M10 11.3a1.6 1.6 0 0 1 3 .5c0 1-1.5 1.5-1.5 2.2" />
    <line x1={12} y1={17} x2={12} y2={17.01} />
  </>,
);
export const Image = svg(
  <>
    <rect x={3} y={3} width={18} height={18} rx={2} />
    <circle cx={9} cy={9} r={2} />
    <path d="m21 15-3.1-3.1a2 2 0 0 0-2.8 0L6 21" />
  </>,
);
export const ShieldCheck = svg(
  <>
    <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1Z" />
    <path d="m9 12 2 2 4-4" />
  </>,
);
export const ShieldOff = svg(
  <>
    <path d="M19.7 14a10.4 10.4 0 0 0 .3-1V6a1 1 0 0 0-1-1c-2 0-4.5-1.2-6.24-2.72a1.17 1.17 0 0 0-1.52 0c-.46.4-1 .8-1.55 1.14" />
    <path d="M4.73 4.73 4 5v8c0 5 3.5 7.5 7.66 8.95a1 1 0 0 0 .67-.01c1.95-.68 3.65-1.74 4.9-3.16" />
    <line x1={2} y1={2} x2={22} y2={22} />
  </>,
);
export const X = svg(
  <>
    <line x1={18} y1={6} x2={6} y2={18} />
    <line x1={6} y1={6} x2={18} y2={18} />
  </>,
);
export const Check = svg(<path d="M20 6 9 17l-5-5" />);
export const ChevronRight = svg(<path d="m9 18 6-6-6-6" />);
export const ChevronLeft = svg(<path d="m15 18-6-6 6-6" />);
export const ChevronUp = svg(<path d="m18 15-6-6-6 6" />);
export const ChevronDown = svg(<path d="m6 9 6 6 6-6" />);
export const Search = svg(
  <>
    <circle cx={11} cy={11} r={8} />
    <path d="m21 21-4.3-4.3" />
  </>,
);
export const Info = svg(
  <>
    <circle cx={12} cy={12} r={10} />
    <line x1={12} y1={16} x2={12} y2={12} />
    <line x1={12} y1={8} x2={12} y2={8.01} />
  </>,
);
export const Alert = svg(
  <>
    <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
    <line x1={12} y1={9} x2={12} y2={13} />
    <line x1={12} y1={17} x2={12} y2={17.01} />
  </>,
);
export const Mail = svg(
  <>
    <rect x={2} y={4} width={20} height={16} rx={2} />
    <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" />
  </>,
);
export const User = svg(
  <>
    <path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2" />
    <circle cx={12} cy={7} r={4} />
  </>,
);
export const Message = svg(
  <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />,
);
export const Eye = svg(
  <>
    <path d="M2.06 12.35a1 1 0 0 1 0-.7 10.75 10.75 0 0 1 19.88 0 1 1 0 0 1 0 .7 10.75 10.75 0 0 1-19.88 0" />
    <circle cx={12} cy={12} r={3} />
  </>,
);
export const EyeOff = svg(
  <>
    <path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68" />
    <path d="M6.61 6.61A13.5 13.5 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61" />
    <line x1={2} y1={2} x2={22} y2={22} />
  </>,
);
export const WrapText = svg(
  <>
    <line x1={3} y1={6} x2={21} y2={6} />
    <path d="M3 12h15a3 3 0 1 1 0 6h-4" />
    <polyline points="16 16 14 18 16 20" />
    <line x1={3} y1={18} x2={10} y2={18} />
  </>,
);
export const Loader = svg(
  <>
    <line x1={12} y1={2} x2={12} y2={6} />
    <line x1={12} y1={18} x2={12} y2={22} />
    <line x1={4.93} y1={4.93} x2={7.76} y2={7.76} />
    <line x1={16.24} y1={16.24} x2={19.07} y2={19.07} />
    <line x1={2} y1={12} x2={6} y2={12} />
    <line x1={18} y1={12} x2={22} y2={12} />
    <line x1={4.93} y1={19.07} x2={7.76} y2={16.24} />
    <line x1={16.24} y1={7.76} x2={19.07} y2={4.93} />
  </>,
);
export const Zap = svg(
  <path d="M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z" />,
);
export const Copy = svg(
  <>
    <rect x={8} y={8} width={14} height={14} rx={2} />
    <path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2" />
  </>,
);
export const Trash = svg(
  <>
    <path d="M3 6h18" />
    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6" />
    <path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
  </>,
);
export const Plus = svg(
  <>
    <line x1={12} y1={5} x2={12} y2={19} />
    <line x1={5} y1={12} x2={19} y2={12} />
  </>,
);
export const FilePlus = svg(
  <>
    <path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z" />
    <path d="M14 2v5h5" />
    <line x1={12} y1={11} x2={12} y2={17} />
    <line x1={9} y1={14} x2={15} y2={14} />
  </>,
);
export const Cpu = svg(
  <>
    <rect x={4} y={4} width={16} height={16} rx={2} />
    <rect x={9} y={9} width={6} height={6} />
    <line x1={9} y1={1} x2={9} y2={4} />
    <line x1={15} y1={1} x2={15} y2={4} />
    <line x1={9} y1={20} x2={9} y2={23} />
    <line x1={15} y1={20} x2={15} y2={23} />
    <line x1={20} y1={9} x2={23} y2={9} />
    <line x1={20} y1={14} x2={23} y2={14} />
    <line x1={1} y1={9} x2={4} y2={9} />
    <line x1={1} y1={14} x2={4} y2={14} />
  </>,
);
export const Package = svg(
  <>
    <path d="m7.5 4.27 9 5.15" />
    <path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z" />
    <path d="m3.3 7 8.7 5 8.7-5" />
    <line x1={12} y1={22} x2={12} y2={12} />
  </>,
);
