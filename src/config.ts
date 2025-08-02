export const SITE = {
  website: "https://0xmuzamil.dev/", // replace this with your deployed domain
  author: "0xMuzamil",
  profile: "https://0xmuzamil.dev/",
  desc: "A tech blog by Muzamil sharing writeups and insights on cybersecurity, hacking, Linux, DevOps, and automation.",
  title: "0xMuzamil",
  ogImage: "astropaper-og.jpg",
  lightAndDarkMode: true,
  postPerIndex: 4,
  postPerPage: 4,
  scheduledPostMargin: 15 * 60 * 1000, // 15 minutes
  showArchives: true,
  showBackButton: true, // show back button in post detail
  editPost: {
    enabled: true,
    text: "Edit page",
    url: "https://github.com/muzi5622/0xmuzamil/edit/main/",
  },
  dynamicOgImage: true,
  dir: "ltr", // "rtl" | "auto"
  lang: "en", // html lang code. Set this empty and default will be "en"
  timezone: "Asia/Bangkok", // Default global timezone (IANA format) https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
} as const;
