/** Inline SVG icons (offline; no icon fonts or CDNs). All inherit ``currentColor``. */

interface IconProps {
  size?: number;
  className?: string;
}

function svg(paths: string, viewBox = '0 0 24 24') {
  function Icon({ size = 18, className }: IconProps) {
    return (
      <svg
        width={size}
        height={size}
        viewBox={viewBox}
        fill="none"
        stroke="currentColor"
        strokeWidth={1.8}
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
        focusable="false"
        className={className}
      >
        {paths.split('|').map((d) => (
          <path key={d} d={d} />
        ))}
      </svg>
    );
  }
  return Icon;
}

export const MenuIcon = svg('M4 6h16|M4 12h16|M4 18h16');
export const SearchIcon = svg('M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14z|M21 21l-4.3-4.3');
export const BellIcon = svg('M18 8a6 6 0 1 0-12 0c0 7-3 9-3 9h18s-3-2-3-9|M13.7 21a2 2 0 0 1-3.4 0');
export const UserIcon = svg('M20 21a8 8 0 0 0-16 0|M12 13a5 5 0 1 0 0-10 5 5 0 0 0 0 10z');
export const ChevronRight = svg('M9 6l6 6-6 6');
export const ChevronDown = svg('M6 9l6 6 6-6');
export const ArrowRight = svg('M5 12h14|M13 6l6 6-6 6');
export const ArrowBack = svg('M19 12H5|M11 18l-6-6 6-6');
export const ShieldIcon = svg('M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z');
export const InsightsIcon = svg('M4 20V10|M10 20V4|M16 20v-7|M22 20H2');
export const EventsIcon = svg('M4 5h16v14H4z|M4 9h16|M8 13h8|M8 16h5');
export const ObjectsIcon = svg('M12 3l9 5-9 5-9-5z|M3 13l9 5 9-5');
export const DevicesIcon = svg('M3 5h18v6H3z|M3 13h18v6H3z|M7 8h.01|M7 16h.01');
export const LinkIcon = svg('M10 14a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1|M14 10a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1');
export const PlugIcon = svg('M9 2v6|M15 2v6|M6 8h12v3a6 6 0 0 1-12 0z|M12 17v5');
export const WrenchIcon = svg('M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.5 2.5-2.5-2.5z');
export const AdminIcon = svg('M16 21v-2a4 4 0 0 0-8 0v2|M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z|M20 8v6|M23 11h-6');
export const LockIcon = svg('M5 11h14v10H5z|M8 11V7a4 4 0 0 1 8 0v4');
export const FilterIcon = svg('M3 5h18l-7 8v6l-4 2v-8z');
export const CheckCircle = svg('M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z|M8 12l3 3 5-6');
export const EmptyCircle = svg('M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z');
export const BlockIcon = svg('M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z|M5 5l14 14');
export const AllowIcon = svg('M4 4h16v16H4z|M9 8l4 4-4 4');
export const EyeIcon = svg('M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z|M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z');
export const FileIcon = svg('M14 3H6v18h12V7z|M14 3v4h4');
export const LogIcon = svg('M5 3h14v18H5z|M9 8h6|M9 12h6|M9 16h4');
export const ZoneIcon = svg('M12 3l7 4v5c0 4-3 7-7 9-4-2-7-5-7-9V7z|M9 12h6');
export const AssetsIcon = svg('M4 7h16v13H4z|M8 7V4h8v3|M4 12h16');
export const ScoreIcon = svg('M12 2l3 6 7 1-5 5 1 7-6-3-6 3 1-7-5-5 7-1z');
